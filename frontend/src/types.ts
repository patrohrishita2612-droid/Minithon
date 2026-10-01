export type Exposure = 'High' | 'Medium' | 'Low';

export type Account = {
  id: string;
  name: string;
  type: string;
  email: string;
  exposure: Exposure;
  riskScore: number;
  twoFA: boolean;
  passwordReused: boolean;
  permissions: string;
  lastActive: string;
  compromised?: boolean;
};

export type BreachEvent = {
  id: string;
  accountId: string;
  accountName: string;
  message: string;
  severity: 'critical' | 'high' | 'medium';
  time: string;
};

export type AddAccountInput = Omit<Account, 'id' | 'exposure' | 'riskScore' | 'lastActive' | 'compromised'>;
