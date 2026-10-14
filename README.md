# Axium Cyber LLC — Website

A responsive, static website for **Axium Cyber LLC**, styled around the neon-blue, metallic-gold Anubis cyberpunk brand.

## Contents

- `index.html` — complete responsive website
- `assets/axium-hero.png` — Axium Cyber landscape artwork
- `_headers` — recommended HTTP security headers and static asset caching for Cloudflare Pages
- `_redirects` — optional single-page fallback redirect
- `robots.txt` — crawler guidance
- `LICENSE` — placeholder license notice; confirm your preferred license before publishing

## Preview locally

No build tools or package installation are required.

1. Download or clone this repository.
2. Keep `index.html` and the `assets/` directory together.
3. Open `index.html` in a modern browser.

## Deploy with Cloudflare Pages (Git integration)

This is a plain static HTML/CSS/JavaScript site. **No framework, build command, or Node.js installation is required.**

1. Create a new GitHub repository, for example `axium-cyber-website`.
2. Upload the contents of this folder to the repository root. Make sure `index.html` is at the root, not inside an extra nested folder.
3. In the Cloudflare dashboard, open **Workers & Pages** and create a **Pages** project connected to Git.
4. Select the GitHub repository and configure:
   - **Production branch:** `main` (or the branch you chose)
   - **Framework preset:** `None`
   - **Build command:** leave blank
   - **Build output directory:** `/` (the repository root; if the dashboard rejects `/`, use `.`)
5. Save and deploy. Cloudflare Pages will provide a `*.pages.dev` address.
6. Later pushes to the production branch will trigger new deployments automatically.

Cloudflare dashboard labels can change slightly. Follow the current Pages Git-integration flow if a label differs.

## Alternative: deploy with Wrangler

If you prefer the command line and have Node.js installed:

```bash
npx wrangler pages deploy . --project-name=axium-cyber-website
```

Use this only after creating the Pages project, or follow Wrangler's prompts. Do not deploy your `.git` directory or secret files.

## Before going live

- Replace placeholder business copy with accurate descriptions of services you actually provide.
- The contact form currently opens a pre-filled draft in the visitor's default email application. It does **not** send or store messages on a server. For a production contact form, connect a form service or backend and add spam protection.
- Add your preferred contact email and business contact details.
- Add a custom domain in Cloudflare Pages if you own one.
- Confirm image and brand asset usage rights.
- Add a privacy policy if you collect personal data through a form or analytics.
- Review legal, accessibility, and security requirements applicable to your business.

## Editing

The page is intentionally dependency-free. Edit `index.html` directly. Keep the hero image path as `assets/axium-hero.png`, or update the `<img>` source if you rename it.
