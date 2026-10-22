# Diagnostics — 23 October 2026

Follow-up: the dependency findings recorded here were resolved by the
[security remediation](security-2026-10-23.md), with clean npm, Python, and Rust audits.

Local review of the card actions, themes, address tools, walkthrough, optional
experiments, exports, protocol checks, and declared dependencies.

## Corrections

- Home, Tools, and the walkthrough now share blue primary actions with light text
  in both themes. Secondary actions retain their outline treatment.
- Dark mode uses separate background, panel, and inset colors. Native fields
  follow the active color scheme. An explicit saved theme overrides the initial
  system preference.
- Secondary text and highlighted address characters have stronger contrast.
  Browser tests measure at least 4.5:1 for the checked action labels, card text,
  and QR/PDF descriptions, including primary-action hover states.
- Updated DOMPurify 3.4.2 → 3.4.17, fflate 0.8.2 → 0.8.3,
  Pillow 11.2.1 → 11.3.0, and Werkzeug 3.1.8 → 3.1.9.

## Verification

| Check | Result |
| --- | --- |
| `npm ci` | Passed with the committed lockfile |
| `npm run lint` | No errors |
| `npm test` | 50 passed |
| `npm run build` | Passed |
| `npm run test:e2e` | 59 passed |
| `api/venv/bin/python -m pytest -q` | 173 passed, including both complete recipient-limit cases |
| `cargo test --locked --manifest-path native/vanity/Cargo.toml` | 42 passed |
| `api/venv/bin/python -m pip check` | No broken requirements |

Browser coverage includes theme persistence, initial system preference, native
form controls, keyboard access, 320px layouts, both languages, generation,
vanity effects, clipboard values, decoded QR downloads, and PDF contents.
Visual review covers Home, Tools, Demo, Privacy, all four Studio workbenches,
and generated-address dialogs at 320px and 1280px in both themes. These local
screens also showed no horizontal overflow or uncaught JavaScript errors.

## Dependency findings at the original review

- **Frontend production:** `npm audit --omit=dev` reports zero findings after
  the DOMPurify and fflate updates.
- **Development tooling:** the full npm audit still reports 18 affected
  packages: 2 critical, 11 high, 4 moderate, and 1 low. These belong to the
  development dependency tree, including `concurrently`/`shell-quote`, Vite,
  Vitest, PostCSS, and Tailwind's glob dependencies. Compatible update attempts,
  including after a clean `npm ci`, fail inside npm with
  `Cannot read properties of null (reading 'edgesOut')`. Some findings also
  require a Tailwind major upgrade according to the audit. No forced upgrade
  or suppression was applied.
- **Python:** `pip-audit --disable-pip --no-deps -r api/requirements.txt` still
  flags Pillow 11.3.0. Its report contains 52 distinct advisory IDs, with fixes
  listed in newer major versions. The Werkzeug finding is resolved. This audit
  covers packages pinned in the production requirements; it does not cover the
  legacy notebook environment or unlisted transitive packages. The audit tool
  ran in a temporary environment, outside the project's runtime environment.

These dependency findings need a separate maintenance change with compatibility
and export checks. This review verifies local behavior; a live Vercel deployment
was not inspected.
