# Release checklist

## Automated gates

- [ ] Run `npm ci` from the committed lockfile.
- [ ] Run `npm run check:release` and confirm every test and the production build pass.
- [ ] Run `npm audit --omit=dev --audit-level=high` with network access.
- [ ] Run `git diff --check` and review the complete diff.
- [ ] Confirm the CI workflow passes on Windows.

## Manual functional checks

- [ ] Exercise every category and target in the browser.
- [ ] Verify one validated, conditional, and legacy output and read its prerequisite note.
- [ ] Copy individual and combined text variants.
- [ ] Download UTF-16LE and UTF-16BE XXE files and verify their BOM/encoding.
- [ ] Confirm complex quotes/comments and pre-encoded `%20`, `%09`, `%0a`, `%0d%0a`, and `+` survive as intended.
- [ ] Confirm large or unsupported inputs fail clearly without stale output.

## Site and release checks

- [ ] Review the title, description, visible intro, FAQ, legal notice, robots.txt, sitemap, and structured data.
- [ ] Confirm Cloudflare Web Analytics records a production page view and does not receive payload values.
- [ ] Build locally and preview the exact `dist` artifact.
- [ ] Confirm the repository, `gh-pages` branch, and `waf-bypass.dev` are the intended targets.
- [ ] Deploy only with `npm run deploy -- --confirm-deploy`.
- [ ] Verify the live page, analytics, HTTPS, and the deployed revision after publication.
