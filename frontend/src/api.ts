import type { Account, AddAccountInput, BreachEvent, Exposure } from './types';

/**
 * TraceRisk API client
 * Connects frontend UI seamlessly to the FastAPI backend with real-time exposure
 * and risk calculations, breach simulations, and account inventory management.
 */

const API_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');

export interface TraceRiskApi {
  getAccounts(): Promise<Account[]>;
  addAccount(input: AddAccountInput): Promise<Account>;
  updateAccount(id: string, patch: Partial<Account>): Promise<Account>;
  simulateBreach(accountId: string): Promise<BreachEvent>;
}

// Category mapping helper
const CATEGORY_TO_TYPE: Record<string, string> = {
  EMAIL: 'Identity',
  PRODUCTIVITY: 'Work',
  DEVELOPMENT: 'Work',
  ENTERTAINMENT: 'Entertainment',
  SHOPPING: 'Shopping',
  FINANCE: 'Finance',
  SOCIAL_MEDIA: 'Social',
  OTHER: 'Identity',
};

const TYPE_TO_CATEGORY: Record<string, string> = {
  Identity: 'EMAIL',
  Work: 'PRODUCTIVITY',
  Entertainment: 'ENTERTAINMENT',
  Shopping: 'SHOPPING',
  Finance: 'FINANCE',
  Social: 'SOCIAL_MEDIA',
};

function formatLastActive(dateStr?: string | null): string {
  if (!dateStr) return 'Recent';
  try {
    const d = new Date(dateStr);
    const now = new Date();
    const diffHours = Math.floor((now.getTime() - d.getTime()) / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);
    if (diffHours < 2) return 'Just now';
    if (diffDays <= 0) return 'Today';
    if (diffDays === 1) return 'Yesterday';
    return `${diffDays} days ago`;
  } catch {
    return 'Recent';
  }
}

function mapExposure(riskLevel?: string, score?: number): Exposure {
  if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH' || (score !== undefined && score >= 70)) {
    return 'High';
  }
  if (riskLevel === 'MEDIUM' || (score !== undefined && score >= 48)) {
    return 'Medium';
  }
  return 'Low';
}

// Active user session state
let cachedUserId: string | null = null;

async function getOrCreateUserId(): Promise<string> {
  if (cachedUserId) return cachedUserId;

  const stored = localStorage.getItem('tracerisk_user_id');
  if (stored) {
    try {
      const res = await fetch(`${API_BASE}/api/users/${stored}`);
      if (res.ok) {
        cachedUserId = stored;
        return stored;
      }
    } catch {
      // Backend maybe reseeded or different DB
    }
  }

  // Lookup demo user
  try {
    const listRes = await fetch(`${API_BASE}/api/users?email=demo@company.com`);
    if (listRes.ok) {
      const json = await listRes.json();
      if (json.success && json.data && json.data.length > 0) {
        const id = json.data[0].id;
        cachedUserId = id;
        localStorage.setItem('tracerisk_user_id', id);
        return id;
      }
    }

    // Create user if not present
    const createRes = await fetch(`${API_BASE}/api/users`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Demo User', email: 'demo@company.com' }),
    });
    if (createRes.ok) {
      const json = await createRes.json();
      const id = json.data.id;
      cachedUserId = id;
      localStorage.setItem('tracerisk_user_id', id);
      return id;
    }
  } catch (err) {
    console.warn('[TraceRisk API] Unable to connect to backend user endpoint:', err);
  }

  // Fallback ID if offline
  return 'demo-user-fallback';
}

// In-memory fallback in case the backend is completely unreachable
let fallbackAccounts: Account[] = [
  { id: 'google', name: 'Google', type: 'Identity', email: 'demo@google.com', exposure: 'High', riskScore: 76, twoFA: false, passwordReused: true, permissions: 'Broad account access', lastActive: 'Today' },
  { id: 'microsoft', name: 'Microsoft', type: 'Work', email: 'demo@microsoft.com', exposure: 'Medium', riskScore: 54, twoFA: true, passwordReused: false, permissions: 'Calendar + profile', lastActive: 'Yesterday' },
  { id: 'spotify', name: 'Spotify', type: 'Entertainment', email: 'demo@spotify.com', exposure: 'Medium', riskScore: 58, twoFA: false, passwordReused: true, permissions: 'Profile + playback', lastActive: '2 days ago' },
  { id: 'amazon', name: 'Amazon', type: 'Shopping', email: 'demo@amazon.com', exposure: 'High', riskScore: 82, twoFA: false, passwordReused: true, permissions: 'Broad account access', lastActive: '4 days ago' },
];

export const traceRiskApi: TraceRiskApi = {
  async getAccounts(): Promise<Account[]> {
    try {
      const userId = await getOrCreateUserId();

      // Parallel fetch footprint, risk, and breaches
      const [footprintRes, riskRes, breachesRes] = await Promise.all([
        fetch(`${API_BASE}/api/users/${userId}/footprint`),
        fetch(`${API_BASE}/api/users/${userId}/risk`),
        fetch(`${API_BASE}/api/users/${userId}/breaches`),
      ]);

      if (!footprintRes.ok) {
        throw new Error(`Footprint API error: ${footprintRes.status}`);
      }

      const footprintData = await footprintRes.json();
      const riskData = riskRes.ok ? await riskRes.json() : null;
      const breachesData = breachesRes.ok ? await breachesRes.json() : null;

      const rawAccounts: any[] = footprintData.data?.accounts || [];
      const rawPermissions: any[] = footprintData.data?.permissions || [];
      const accountRisks: any[] = riskData?.data?.account_risks || [];
      const breaches: any[] = breachesData?.data?.breaches || [];

      if (rawAccounts.length === 0) {
        // If DB has no accounts for this user yet, fallback to seed
        return fallbackAccounts;
      }

      const mapped: Account[] = rawAccounts.map((acc: any) => {
        const riskItem = accountRisks.find((r: any) => r.account_id === acc.id);
        const accBreaches = breaches.filter((b: any) => b.account_id === acc.id);
        const isCompromised = accBreaches.length > 0;

        const score = riskItem ? Math.round(riskItem.score) : isCompromised ? 92 : 50;
        const exposure = mapExposure(riskItem?.risk_level, score);

        const perms = rawPermissions
          .filter((p: any) => p.account_id === acc.id)
          .map((p: any) => p.permission_type)
          .filter(Boolean);

        const category = acc.service?.category;
        const type = category ? (CATEGORY_TO_TYPE[category] || 'Identity') : 'Identity';

        return {
          id: acc.id,
          name: acc.display_name || acc.service?.name || 'Account',
          type,
          email: acc.account_identifier,
          exposure: isCompromised ? 'High' : exposure,
          riskScore: isCompromised ? Math.max(score, 92) : score,
          twoFA: Boolean(acc.two_factor_enabled),
          passwordReused: Boolean(acc.password_reuse_group_id),
          permissions: perms.length > 0 ? perms.join(', ') : 'Standard access',
          lastActive: formatLastActive(acc.last_activity),
          compromised: isCompromised,
        };
      });

      // Keep fallback accounts updated as backup
      fallbackAccounts = mapped;
      return mapped;
    } catch (err) {
      console.warn('[TraceRisk API] Failed to fetch accounts from backend, using current state:', err);
      return fallbackAccounts;
    }
  },

  async addAccount(input: AddAccountInput): Promise<Account> {
    try {
      const userId = await getOrCreateUserId();

      // 1. Resolve or create service
      let serviceId: string | null = null;
      try {
        const servicesRes = await fetch(`${API_BASE}/api/services`);
        if (servicesRes.ok) {
          const sJson = await servicesRes.json();
          const services: any[] = sJson.data || [];
          const existing = services.find((s: any) => s.name?.toLowerCase() === input.name.trim().toLowerCase());
          if (existing) {
            serviceId = existing.id;
          }
        }
      } catch {
        // service query failed
      }

      if (!serviceId) {
        const category = TYPE_TO_CATEGORY[input.type] || 'OTHER';
        const createServiceRes = await fetch(`${API_BASE}/api/services`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: input.name.trim(),
            category,
            website: `https://${input.name.toLowerCase().replace(/[^a-z0-9]/g, '')}.com`,
          }),
        });
        if (createServiceRes.ok) {
          const sData = await createServiceRes.json();
          serviceId = sData.data?.id;
        }
      }

      if (!serviceId) {
        throw new Error('Could not resolve service');
      }

      // 2. Create account
      const createAccountRes = await fetch(`${API_BASE}/api/accounts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_id: userId,
          service_id: serviceId,
          account_identifier: input.email.trim(),
          display_name: input.name.trim(),
          status: 'ACTIVE',
          sign_in_method: 'PASSWORD',
          two_factor_enabled: input.twoFA,
          password_reuse_group_id: input.passwordReused ? 'reuse-group-1' : null,
          password_strength: 'MEDIUM',
        }),
      });

      if (!createAccountRes.ok) {
        throw new Error(`Account creation failed: ${createAccountRes.status}`);
      }

      const accData = await createAccountRes.json();
      const account = accData.data;

      // 3. Add permissions if provided
      if (input.permissions && input.permissions.trim()) {
        const parts = input.permissions.split(',').map((p) => p.trim()).filter(Boolean);
        for (const perm of parts) {
          const isHigh = perm.toLowerCase().includes('camera') || perm.toLowerCase().includes('location') || perm.toLowerCase().includes('broad');
          await fetch(`${API_BASE}/api/accounts/${account.id}/permissions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              permission_type: perm,
              sensitivity: isHigh ? 'HIGH' : 'MEDIUM',
              granted: true,
            }),
          }).catch(() => null);
        }
      }

      // 4. Recalculate risk on backend
      let riskScore = 45;
      let exposure: Exposure = 'Low';
      try {
        const riskCalcRes = await fetch(`${API_BASE}/api/users/${userId}/risk/calculate`, {
          method: 'POST',
        });
        if (riskCalcRes.ok) {
          const rJson = await riskCalcRes.json();
          const ar = rJson.data?.account_risks?.find((r: any) => r.account_id === account.id);
          if (ar) {
            riskScore = Math.round(ar.score);
            exposure = mapExposure(ar.risk_level, riskScore);
          }
        }
      } catch {
        // calculation fallback
        riskScore = input.twoFA ? 35 : 75;
        exposure = riskScore >= 70 ? 'High' : riskScore >= 48 ? 'Medium' : 'Low';
      }

      const newAccount: Account = {
        id: account.id,
        name: account.display_name || input.name,
        type: input.type,
        email: account.account_identifier,
        exposure,
        riskScore,
        twoFA: Boolean(account.two_factor_enabled),
        passwordReused: Boolean(account.password_reuse_group_id),
        permissions: input.permissions || 'Standard access',
        lastActive: 'Just now',
        compromised: false,
      };

      fallbackAccounts = [newAccount, ...fallbackAccounts];
      return newAccount;
    } catch (err) {
      console.warn('[TraceRisk API] Backend addAccount failed, using offline mode:', err);
      const score = input.twoFA ? 36 : 78;
      const account: Account = {
        ...input,
        id: `${input.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${Date.now()}`,
        riskScore: score,
        exposure: score >= 70 ? 'High' : score >= 48 ? 'Medium' : 'Low',
        lastActive: 'Just now',
        compromised: false,
      };
      fallbackAccounts = [account, ...fallbackAccounts];
      return account;
    }
  },

  async updateAccount(id: string, patch: Partial<Account>): Promise<Account> {
    try {
      const userId = await getOrCreateUserId();

      // If resolving simulated breach, clear breach events
      if (patch.compromised === false) {
        await fetch(`${API_BASE}/api/accounts/${id}/breaches`, {
          method: 'DELETE',
        }).catch(() => null);
      }

      // Build AccountUpdate payload
      const payload: Record<string, any> = {};
      if (patch.name !== undefined) payload.display_name = patch.name;
      if (patch.email !== undefined) payload.account_identifier = patch.email;
      if (patch.twoFA !== undefined) payload.two_factor_enabled = patch.twoFA;
      if (patch.passwordReused !== undefined) {
        payload.password_reuse_group_id = patch.passwordReused ? 'reuse-group-1' : null;
      }

      if (Object.keys(payload).length > 0) {
        await fetch(`${API_BASE}/api/accounts/${id}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      }

      // If permissions updated, add updated permission
      if (patch.permissions !== undefined) {
        await fetch(`${API_BASE}/api/accounts/${id}/permissions`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            permission_type: patch.permissions,
            sensitivity: patch.permissions.toLowerCase().includes('broad') ? 'HIGH' : 'LOW',
            granted: true,
          }),
        }).catch(() => null);
      }

      // Recalculate risk on backend
      let riskScore = patch.riskScore;
      let exposure = patch.exposure;
      try {
        const riskCalcRes = await fetch(`${API_BASE}/api/users/${userId}/risk/calculate`, {
          method: 'POST',
        });
        if (riskCalcRes.ok) {
          const rJson = await riskCalcRes.json();
          const ar = rJson.data?.account_risks?.find((r: any) => r.account_id === id);
          if (ar) {
            riskScore = Math.round(ar.score);
            exposure = mapExposure(ar.risk_level, riskScore);
          }
        }
      } catch {
        // fallback
      }

      const idx = fallbackAccounts.findIndex((a) => a.id === id);
      const existing = idx >= 0 ? fallbackAccounts[idx] : null;

      const updated: Account = {
        id,
        name: patch.name || existing?.name || 'Account',
        type: patch.type || existing?.type || 'Identity',
        email: patch.email || existing?.email || '',
        exposure: exposure || patch.exposure || existing?.exposure || 'Low',
        riskScore: riskScore ?? patch.riskScore ?? existing?.riskScore ?? 45,
        twoFA: patch.twoFA !== undefined ? patch.twoFA : (existing?.twoFA ?? false),
        passwordReused: patch.passwordReused !== undefined ? patch.passwordReused : (existing?.passwordReused ?? false),
        permissions: patch.permissions || existing?.permissions || 'Standard access',
        lastActive: existing?.lastActive || 'Just now',
        compromised: patch.compromised !== undefined ? patch.compromised : existing?.compromised,
      };

      if (idx >= 0) {
        fallbackAccounts[idx] = updated;
      }
      return updated;
    } catch (err) {
      console.warn('[TraceRisk API] Backend updateAccount failed, falling back:', err);
      const idx = fallbackAccounts.findIndex((a) => a.id === id);
      if (idx >= 0) {
        fallbackAccounts[idx] = { ...fallbackAccounts[idx], ...patch };
        return fallbackAccounts[idx];
      }
      throw err;
    }
  },

  async simulateBreach(accountId: string): Promise<BreachEvent> {
    try {
      const res = await fetch(`${API_BASE}/api/accounts/${accountId}/breaches`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: 'Simulated Credential Leak',
          description: 'Credentials detected in simulated breach repository. Immediate containment advised.',
          severity: 'CRITICAL',
        }),
      });

      if (!res.ok) {
        throw new Error(`Breach simulation API failed: ${res.status}`);
      }

      const json = await res.json();
      const eventData = json.data;

      const idx = fallbackAccounts.findIndex((a) => a.id === accountId);
      const account = idx >= 0 ? fallbackAccounts[idx] : null;
      const accountName = eventData?.service_name || account?.name || 'Account';

      if (account) {
        fallbackAccounts[idx] = {
          ...account,
          compromised: true,
          exposure: 'High',
          riskScore: Math.max(account.riskScore, 92),
        };
      }

      return {
        id: eventData?.id || `breach-${Date.now()}`,
        accountId,
        accountName,
        severity: 'critical',
        message: `${accountName} was marked compromised. Review linked recovery paths and revoke unnecessary access.`,
        time: 'Just now',
      };
    } catch (err) {
      console.warn('[TraceRisk API] Backend simulateBreach failed, using local simulation:', err);
      const idx = fallbackAccounts.findIndex((a) => a.id === accountId);
      const account = idx >= 0 ? fallbackAccounts[idx] : null;
      const accountName = account?.name || 'Account';

      if (account) {
        fallbackAccounts[idx] = {
          ...account,
          compromised: true,
          exposure: 'High',
          riskScore: Math.max(account.riskScore, 92),
        };
      }

      return {
        id: `breach-${Date.now()}`,
        accountId,
        accountName,
        severity: 'critical',
        message: `${accountName} was marked compromised. Review linked recovery paths and revoke unnecessary access.`,
        time: 'Just now',
      };
    }
  },
};
