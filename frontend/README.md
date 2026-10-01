# TraceRisk Frontend v4

React + TypeScript + Vite frontend for the TraceRisk Digital Footprint & Privacy Risk Auditor.

## Run

```bash
npm install
npm run dev
```

## Product structure

Navbar pages:

1. **Home** — high-risk accounts at the top, account inventory with sort/filter controls, Add Account, simple Privacy Dashboard and next steps.
2. **Link** — dedicated connected-account management page.
3. **Breach simulator** — account selector, functional simulated breach and large account-focused risk network.
4. **Reduce risk** — account-specific checklist. Password remediation opens a centered requirements modal with 12-character, upper/lowercase, number, symbol, uniqueness and guessability checks.
5. **Account** — profile/account info, edit settings, account switching, notification toggle, add another account and logout.
6. **Contact** — support email and issue/feedback form.

## Backend seam

`src/api.ts` contains the mock API interface:

- `getAccounts()`
- `addAccount()`
- `updateAccount()`
- `simulateBreach()`

Replace those implementations with real API requests later; the page components already consume the interface rather than directly managing persistence.

## Current demo behavior

- Any non-empty login email/password grants access.
- Adding an account updates Home, Link, Reduce Risk and the risk graph.
- Breach simulation updates the selected account, risk score, network and red risk alert.
- The breach alert links directly to the selected account's Reduce Risk checklist.
- Modal dialogs are viewport-centered and lock page scrolling; only the modal body can scroll if needed.
