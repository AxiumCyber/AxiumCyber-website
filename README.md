# Axium Cyber LLC Website and Staff Portal

A responsive public website and Cloudflare-backed staff operations portal for Axium Cyber LLC.

## Contents

- `index.html` — public website
- `staff.html` and `staff-app.js` — staff dashboard and API client
- `functions/api/[[path]].js` — Cloudflare Pages API with local sessions, password hashing, and server-side role checks
- `migrations/0001_initial.sql` and `migrations/0002_local_staff_auth.sql` — D1 schema for staff credentials, customers, support, authorized engagements, and forensic metadata
- `wrangler.toml` — Pages configuration, D1/KV bindings, and non-secret variables; replace its placeholders before deploying
- `assets/axium-hero.png` — Axium Cyber hero artwork
- `_headers` — HTTP security headers and staff-page Content Security Policy
- `_redirects` — optional Pages redirects
- `robots.txt` — crawler guidance
- `LICENSE` — placeholder; confirm the intended license before publishing

## Public Site Preview

The public site is static and can be previewed by opening `index.html` in a browser. Keep the `assets/` directory beside it. The staff portal cannot be safely previewed from a local file: it requires Cloudflare Pages Functions and D1. Do not enter real customer or staff information until the deployment steps below are complete.

## Requirements

- A Cloudflare account with Workers & Pages, D1, and Workers KV available
- Node.js and npm if using Wrangler from PowerShell
- A verified Resend sender and API key if staff email notices are desired (email is optional)

## Configure Cloudflare Pages

1. In Cloudflare, create a Pages project connected to this GitHub repository. Set the production branch to your deployment branch, framework preset to `None`, build command to blank, and build output directory to `.` (the repository root). The repository includes `wrangler.toml` and a Pages Functions route under `functions/`.
2. Create a D1 database named `axium-cyber-portal`. Alternatively, from PowerShell in the repository, run `npx wrangler d1 create axium-cyber-portal`. Copy the returned database ID into `database_id` in `wrangler.toml`; replace `REPLACE_WITH_D1_DATABASE_ID`.
3. Create a KV namespace for the non-sensitive security-tool catalog cache:

   ```powershell
   npx wrangler kv namespace create axium-portal-cache
   ```

   Copy the returned namespace ID into the `PORTAL_CACHE` `id` in `wrangler.toml`, replacing `REPLACE_WITH_KV_NAMESPACE_ID`. D1 remains the source of truth for accounts, password hashes, sessions, customers, tickets, and audit records; do not move these to KV.
4. Do not put Cloudflare Access in front of `/staff.html`, `/staff-app.js`, or `/api/*`; the portal authenticates staff with its own username/password sessions so staff email can be optional.
5. Create a strong one-time bootstrap secret locally. In PowerShell, generate one and enter it when Wrangler prompts; do not commit it or paste it into source files:

   ```powershell
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   npx wrangler pages secret put BOOTSTRAP_SECRET --project-name=axium-cyber-website
   ```

6. If staff email notices are wanted, set `FROM_EMAIL` in `wrangler.toml` to a sender verified by Resend and store the API key as a Pages secret. Never put the key in HTML, JavaScript, or Git:

   ```powershell
   npx wrangler pages secret put RESEND_API_KEY --project-name=axium-cyber-website
   ```

   A personal mailbox may not be accepted as a sender. Use an address/domain verified by your email provider.

Cloudflare dashboard labels can change. Before deploying, confirm the Pages project is using the repository root, the D1 binding is named `DB`, the KV binding is named `PORTAL_CACHE`, and the production Pages environment has the bootstrap secret (and mail secret if used).

## Apply the Database Schema

Install Wrangler if needed, then run these commands from the repository root in PowerShell:

```powershell
npm install --global wrangler
npx wrangler login
npx wrangler d1 migrations apply axium-cyber-portal --remote
```

The migrations create the staff directory and credential/session tables, customer records, support tickets and notes, security engagement approvals, forensic case metadata, evidence hashes, and append-only audit/custody event tables. They do not create a default account or password.

## Create the First Administrator

After deploying the migration and setting `BOOTSTRAP_SECRET`, open `/staff.html`. The first-admin form defaults the username to `admin`; set a strong password and optionally enter an email. The password is salted and hashed by the API. Remove the bootstrap secret after setup:

```powershell
npx wrangler pages secret delete BOOTSTRAP_SECRET --project-name=axium-cyber-website
```

Super Admin-created accounts also require a 12-128 character temporary password and must change it at first sign-in. Email is optional. If configured, Resend sends a notice but never sends the password; share it with the user through a separate secure channel. No default password is shipped.

There is no public password-reset endpoint. A Super Admin must provision a replacement account or follow a separately secured administrative recovery procedure.

## Automatic Deploy and Verify

Use Cloudflare Pages Git integration. Set the production branch to your deployment branch, leave the build command blank, and set the output directory to `.`. Each push to that branch automatically builds and deploys the site; no custom deploy command is needed.

After the automatic deployment completes, verify:

1. Open `/staff.html`; the staff sign-in form should appear.
2. Sign in with an active username/password. The progress indicator should show **Access granted** only after the API verifies the password and creates a session.
3. Create a staff account with and without an email; confirm the email field is optional and the new account must change its temporary password.
4. Add a test customer and confirm it appears after reload. Remove test data before using real customer records.
5. Delete a test account as Super Admin; confirm it disappears, its sessions are revoked, and the last active Super Admin cannot be deleted.
6. Confirm role restrictions: Super Admin manages staff; Support handles the support queue and customer directory; Technical Team sees technical engagements; Forensic Analyst sees forensic cases.

If sign-in fails, check Pages function logs, D1 binding name (`DB`), both migration statuses, the `BOOTSTRAP_SECRET` setup state, username/status in `staff_users`, and that the account is not deleted. Configure edge/API rate limits before production use.

## Security Tools and Forensics Boundaries

- The catalog lists possible integrations for code/dependencies (Semgrep, CodeQL, OSV-Scanner, Trivy), web/API (OWASP ZAP Baseline, Burp Suite), network/services (Nmap, Greenbone), cloud/configuration (Prowler, Checkov), and forensics (Autopsy/Sleuth Kit, Volatility 3, Plaso, KAPE). These tools are not bundled or connected by this website.
- Scanner execution intentionally returns `503` until a separate, network-isolated runner is deployed. A runner must enforce customer-owned allowlists, written authorization, exact scope, dates, approvals, rate/resource limits, and audit logging. Do not run scans against systems without explicit authorization.
- Forensic records contain case/evidence metadata, SHA-256 values, and custody events, not evidence files. The hash history is tamper-evident only, not a legally certified chain of custody. Use a separate access-controlled evidence vault with retention controls and validate jurisdictional requirements with counsel.
- Multi-factor authentication is not implemented in this local-password flow. Add an MFA-capable identity layer or private network gateway before using it for high-risk or regulated data.
- Staff deletion revokes sessions and anonymizes the account while retaining audit/history references required by related records; it is not a hard purge of historical audit data.
- No system is “foolproof.” Configure edge/API rate limits, backups and restore tests, retention/deletion procedures, monitoring, and an independent security review before storing real customer or evidentiary data.

## Public-Site Notes

- Replace placeholder business copy with accurate services and contact details.
- The public contact form opens a pre-filled email draft; it does not send or store messages on a server.
- Confirm image and brand asset rights, add a privacy policy if collecting personal data, and review applicable legal and accessibility requirements.

## Editing

Keep `assets/axium-hero.png` beside `index.html`. Staff interface changes belong in `staff.html` and `staff-app.js`; API, database, and deployment changes require reviewing `functions/`, `migrations/`, and `wrangler.toml` together.
