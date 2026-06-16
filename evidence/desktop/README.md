# Desktop app — launch + branding verification (2026-06-16)

Verifies the Electron desktop app builds, launches, and renders on the clean
Hermes v2026.6.5 rebuild, and that the home-screen wordmark is branded LLIAM-GOV.

- **Build:** `npm run build` (apps/desktop) → `tsc -b` (type-check, incl. the
  branding change) + `vite build`. Full `dist/` produced; `LLIAM-GOV` present in
  the built JS bundle.
- **Launch:** `electron .` under Xvfb (headless), `--no-sandbox` (container is
  root), `HERMES_DESKTOP_BOOT_FAKE=1`. Renderer loaded `dist/index.html`; window
  title "Hermes" (window chrome left intentionally unbranded — no string/process
  retagging per scope).
- **Capture:** via Electron's remote-debugging port (CDP `Page.captureScreenshot`).

## Artifacts
- `launch-2026-06-16.png` — first-run provider/onboarding screen (proves launch +
  provider selection renders).
- `home-2026-06-16.png` — chat home screen showing the **LLIAM-GOV** wordmark in
  blue (#2563eb). Branding confirmed.

Scope note: only the home-screen wordmark was rebranded
(`apps/desktop/src/components/chat/intro.tsx`). Composer/status/window strings
remain upstream by request.
