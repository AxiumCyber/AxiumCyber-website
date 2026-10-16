# Axium Cyber LLC Website and Staff Portal

A responsive public website and Cloudflare-backed staff operations portal for Axium Cyber LLC.

## Contents

- `index.html` — public website
- `staff.html` and `staff-app.js` — staff dashboard and API client
- `functions/api/[[path]].js` — Cloudflare Pages API with Access JWT verification and server-side role checks
- `migrations/0001_initial.sql` — D1 schema for staff, customers, support, authorized engagements, and forensic metadata
- `wrangler.toml` — Pages configuration, D1 binding, and non-secret variables; replace its placeholders before deploying
- `assets/axium-hero.png` — Axium Cyber hero artwork
- `_headers` — HTTP security headers and staff-page Content Security Policy
- `_redirects` — optional Pages redirects
- `robots.txt` — crawler guidance
- `LICENSE` — placeholder; confirm the intended license before publishing

## Public Site Preview

The public site is static and can be previewed by opening `index.html` in a browser. Keep the `assets/` directory beside it. The staff portal cannot be safely previewed from a local file: it requires Cloudflare Pages Functions, D1, and Cloudflare Access. Do not enter real customer or staff information until the deployment steps below are complete.

## Requirements

- A Cloudflare account with Workers & Pages, D1, and Cloudflare Access available
- Node.js and npm if using Wrangler from PowerShell
- A verified sender with Resend (or update the API to use another email provider)
- An identity provider configured in Cloudflare Access, with MFA enabled for staff

## Configure Cloudflare Pages

1. In Cloudflare, create a Pages project connected to this GitHub repository. Set the production branch to your deployment branch, framework preset to `None`, build command to blank, and build output directory to `.` (the repository root). The repository includes `wrangler.toml` and a Pages Functions route under `functions/`.
2. Create a D1 database named `axium-cyber-portal`. Alternatively, from PowerShell in the repository, run `npx wrangler d1 create axium-cyber-portal`. Copy the returned database ID into `database_id` in `wrangler.toml`; replace `REPLACE_WITH_D1_DATABASE_ID`.
3. In Cloudflare Access, create an application protecting `/staff.html`, `/staff-app.js`, and `/api/*` on the Pages hostname (or protect the whole hostname if it is staff-only). Configure an approved identity provider, MFA, and a narrow email/group allow policy.
4. Set `CF_ACCESS_TEAM_DOMAIN` in `wrangler.toml` to the Access team hostname, such as `your-team.cloudflareaccess.com`. Set `CF_ACCESS_AUD` to the application audience tag shown in the Access application. The API verifies the signed JWT, checks the audience and issuer, then maps its email to an active D1 staff record.
5. Configure `FROM_EMAIL` in `wrangler.toml` with a sender verified by Resend. Store the Resend API key as a Pages secret; never put it in HTML, JavaScript, or Git:

   ```powershell
   npx wrangler pages secret put RESEND_API_KEY --project-name=axium-cyber-website
   ```

   A personal mailbox may not be accepted as a sender. Use an address/domain verified by your email provider.

Cloudflare dashboard labels can change. Before deploying, confirm the Pages project is using the repository root, the D1 binding is named `DB`, and the production Pages environment has the configured variables and secret.

## Apply the Database Schema

Install Wrangler if needed, then run these commands from the repository root in PowerShell:

```powershell
npm install --global wrangler
npx wrangler login
npx wrangler d1 migrations apply axium-cyber-portal --remote
```

The migration creates the staff directory, customer records, support tickets and notes, security engagement approvals, forensic case metadata, evidence hashes, and append-only audit/custody event tables. It does not create a default account or password.

## Create the First Administrator

First make sure the administrator can authenticate through the Cloudflare Access identity provider and is allowed by its policy. Then add the initial account directly to D1. Replace `YOUR_ACCESS_EMAIL` with the exact email returned by Cloudflare Access:

```powershell
npx wrangler d1 execute axium-cyber-portal --remote --command "INSERT INTO staff_users (id, username, email, role, status, created_at, updated_at) VALUES (lower(hex(randomblob(16))), 'admin', 'YOUR_ACCESS_EMAIL', 'SUPER ADMIN', 'ACTIVE', strftime('%Y-%m-%dT%H:%M:%fZ','now'), strftime('%Y-%m-%dT%H:%M:%fZ','now'));"
```

The dashboard username is `admin`; sign-in and MFA are handled by Cloudflare Access. There is intentionally no shared or hard-coded password. Do not add a production password to source control or send one by email.

## Deploy and Verify

This repository is a **Cloudflare Pages** project, not a Worker script. Do not set the build/deploy command to `npx wrangler deploy`; that command expects a Worker entry point and fails with “Missing entry-point to Worker script or to assets directory.”

For a Pages Git integration, leave the build command blank and set the output directory to `.`; Pages handles deployment on each push. If your build system has a separate **Deploy command** field, use:

```powershell
npx wrangler pages deploy . --project-name=axium-cyber-website
```

To deploy manually from PowerShell after creating the Pages project and applying its bindings/secrets, run the same command from the repository root:

```powershell
npx wrangler pages deploy . --project-name=axium-cyber-website
```

Then verify the deployment:

1. Open `/staff.html`. An unauthenticated visitor should be challenged by Cloudflare Access.
2. Sign in using the configured identity provider and MFA.
3. Select **Enter Dashboard**. The progress indicator should complete and show **Access granted** only after `/api/me` validates the signed Access assertion and finds an active staff record.
4. Add a test customer and confirm it appears after reload. Remove test data before using real customer records.
5. Invite a test staff identity. The recipient must first be permitted by the Access identity provider/policy; a portal invite alone does not grant Cloudflare Access.
6. Confirm role restrictions: Super Admin manages staff; Support handles the support queue and customer directory; Technical Team sees technical engagements; Forensic Analyst sees forensic cases.

If access fails, check the Pages function logs, D1 binding name (`DB`), D1 migration status, Access team hostname and audience, email claim, and exact email/status in `staff_users`. Do not bypass Access to work around a configuration error.

## Security Tools and Forensics Boundaries

- The catalog lists possible integrations for code/dependencies (Semgrep, CodeQL, OSV-Scanner, Trivy), web/API (OWASP ZAP Baseline, Burp Suite), network/services (Nmap, Greenbone), cloud/configuration (Prowler, Checkov), and forensics (Autopsy/Sleuth Kit, Volatility 3, Plaso, KAPE). These tools are not bundled or connected by this website.
- Scanner execution intentionally returns `503` until a separate, network-isolated runner is deployed. A runner must enforce customer-owned allowlists, written authorization, exact scope, dates, approvals, rate/resource limits, and audit logging. Do not run scans against systems without explicit authorization.
- Forensic records contain case/evidence metadata, SHA-256 values, and custody events, not evidence files. The hash history is tamper-evident only, not a legally certified chain of custody. Use a separate access-controlled evidence vault with retention controls and validate jurisdictional requirements with counsel.
- No system is “foolproof.” Configure edge/API rate limits, backups and restore tests, retention/deletion procedures, monitoring, and an independent security review before storing real customer or evidentiary data.

## Public-Site Notes

- Replace placeholder business copy with accurate services and contact details.
- The public contact form opens a pre-filled email draft; it does not send or store messages on a server.
- Confirm image and brand asset rights, add a privacy policy if collecting personal data, and review applicable legal and accessibility requirements.

## Editing

Keep `assets/axium-hero.png` beside `index.html`. Staff interface changes belong in `staff.html` and `staff-app.js`; API, database, and deployment changes require reviewing `functions/`, `migrations/`, and `wrangler.toml` together.
