# Silent Payments educational PoC

A React + Flask + Rust demonstration of [BIP-352 v1.1.1](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki). It derives silent-payment outputs, scans synthetic transactions, verifies spending signatures, and generates random or vanity addresses. Nothing is broadcast and no blockchain service is required.

The UI defaults to testnet; mainnet remains selectable. **The server generates and sees private keys.** This is an educational tool, not a production wallet. Exports contain independent raw scan/spend keys, not a seed or BIP32 wallet. QR images contain only the public address; PDF backups contain private keys.

## Local setup

Use Node **22.14 or newer**, Python **3.13**, and Rust **1.97.1**. `.nvmrc`, `.python-version`, and `rust-toolchain.toml` record these defaults. Rustup installs the pinned toolchain when Cargo is invoked.

```sh
npm ci
python3.13 -m venv api/venv
api/venv/bin/pip install -r api/requirements-test.txt
npm run build:vanity
npm run dev
```

Open http://localhost:5173. Vite proxies `/api` to Flask on port 5328. `npm run dev` starts both servers and builds Rust; the backend finds the fresh executable under `native/vanity/target`. It never copies over `api/bin/vanity`. Production uses pinned dependencies from `api/requirements.txt`; `api/requirements-dev.txt` additionally supports the legacy notebooks.

## What to try

- Complete the guided sender/receiver walkthrough and the two curated edge cases.
- Open **All reference cases** to select any of the 28 pinned scenario groups, sending/receiving direction, and individual subcase. A successful expected rejection is shown explicitly. Large reference results can be inspected in the expandable actual/expected output.
- Generate random mainnet or testnet addresses, copy the address or keys, and export a public QR or private PDF backup.
- Search for a short vanity substring. A one-character pattern is suitable for smoke tests. Five-character patterns can legitimately exhaust the deployed deadline.

### Navigation and layout

Learning uses full pages: `/?view=walkthrough` and the existing `/?view=reference&case=0&direction=send&subcase=0` links. The header and learning navigation support normal links, new tabs, and browser Back/Forward. Desktop layouts place explanations and reference selectors beside the results; mobile uses normal page scrolling and collapsible reference controls. Walkthrough actions stay within reach as you read.

Address tools remain in a keyboard-accessible dialog. Escape closes it, Tab stays within it, and closing returns focus to the opener. Testnet/Mainnet are explicit radio choices; changing network clears the current result. New results receive focus at their address heading. The server-key notice is separate from generation-mode controls. Light/dark themes, English/Italian, reduced motion, and public QR/private PDF exports remain available.

### Guided learning

The four-stage donation walkthrough always uses reference group 0. Each stage explains its learning goal, who knows which keys, and its expected outcome before showing technical data. Expand **How it works** for the glossary or **Reference values before execution** for published expectations. Actual sender/receiver comparisons appear only after their checks run.

This server simulates both roles using public fixture keys; the API does not expose every intermediate shared-secret calculation and nothing is broadcast. The completion recap links to multiple payments, labels, unrelated outputs, and zero-sum rejection in the reference explorer. Restart resets progress and results; leaving the page aborts browser requests and discards late responses.

### Learning from reference cases

Open **Learn → All reference cases** to explore all 28 pinned groups in English or Italian. Each lesson explains its inputs, expected behavior, and why the case matters before you run it. Published fixture keys are public test data; never use them for funds.

Copy an example link to share a selection, such as `/?view=reference&case=18&direction=receive&subcase=1`. Links select the group, direction, and zero-based subcase without executing a check. Invalid selections fall back visibly to case 0, sending, subcase 0. Returning home removes the selection parameters while retaining unrelated URL parameters. Browser Back and Forward restore the selected page and reference example without automatically running a check.

The runner determines pass/fail. Detailed comparisons account for output order, duplicate counts, all receiving addresses, and exact public-key/tweak pairs. Expected rejection and successful empty discovery have distinct explanations. Large output lists use 50 rows per page; complete JSON and randomized signature evidence remain available in expandable details. Technical details link to the pinned protocol revision.

### Vanity semantics and limits

The simple UI searches for a substring. The API and CLI additionally support `prefix` and `suffix`. Prefix/contains searches begin after `sp1qq` or `tsp1qq`; suffix matching includes the checksum. Compressed scan-key encoding restricts the first prefix symbol to **gf2tvdw0**. Other initial prefix symbols are rejected as impossible.

```sh
native/vanity/target/release/vanity g --mode prefix --threads 2 --timeout 10 --testnet
api/venv/bin/python -m flask --app api.index run --port 5328
```

`VANITY_MAX_PATTERN_LEN`, `VANITY_TIMEOUT_SEC`, and `VANITY_MAX_THREADS` configure local limits (defaults 5 symbols, 600 seconds, 4 workers; hard caps 64 symbols, 86,400 seconds, 64 workers). Vercel defaults/caps the search to 50 seconds and two workers, with a subprocess guard five seconds later, inside a 60-second function limit. Pattern length remains capped at 64; practical deployed default is 5. Invalid environment values fall back to defaults; integer values are clamped to supported bounds.

Closing or changing a request discards its result in the browser. It does not cancel a running serverless function; Rust stops at its deadline. The local Python fallback is bounded as well. Vercel requires a runnable, self-tested Rust executable.

## API compatibility

Successful generation responses retain `addresses`, `key_material`, `network`, `elapsed`, `message`, and `qr_png_base64`. Both keys are lowercase 64-character hex strings, valid scalars strictly between zero and the secp256k1 order.

- `POST /api/get_sp_address`: `{ "testnet": true }`; legacy GET with `?testnet=1` remains supported. Omitted network flags preserve the backend's mainnet default.
- `POST /api/vanity_address`: `{ "pattern": "g", "mode": "prefix", "testnet": true, "threads": 2 }`; the legacy GET route remains supported.
- `GET /api/reference_cases`: group IDs, comments, and direction-specific subcase counts.
- `GET /api/test_case/18?case_index=1`: selected reference details and counts.
- `GET /api/single_test/receive/18?case_index=1`: exact comparison for the selected subcase. Existing routes default to subcase zero. Expected sender failures set `expected_failure: true` and a descriptive `note`.
- `GET /api/health`: protocol version, packaged source revision, runnable binary availability, and runtime limits.

Errors use `{ "error": "…", "code": "…" }`: 400 invalid input, 503 unavailable generator, 504 search deadline, sanitized 500 unexpected failure. Generated-key and reference-detail responses carry `Cache-Control: no-store`.

### Old key exports

Earlier random generation returned 64-byte HMAC outputs and silently truncated them during public-key derivation. Those values are not valid raw secp256k1 private keys. This version rejects them and does not automatically convert or migrate old backups. Recovery is outside this PoC's scope. New exports always contain valid 32-byte keys.

## Verification

```sh
cargo test --locked --manifest-path native/vanity/Cargo.toml
api/venv/bin/python -m pytest -m 'not slow' -q
api/venv/bin/python -m pytest -m slow -q
npm run lint
npm test
npm run build
npx playwright install --with-deps chromium
npm run test:e2e
```

The slow job executes the full official 2,323-output recipient-limit vector. All vectors run without network access. `api/core/test/provenance.json` records upstream commit and source digest; existing scenario IDs 0–25 are preserved and the two new cases are IDs 26–27. The official fixture includes counted recipients and compact expectations, which the shared runner handles explicitly.

Cross-language fixtures verify actual Python/Rust address encoding and checksums. Generated-key tests derive synthetic payments, scan them, and independently verify signatures with libsecp256k1. Production arithmetic uses pinned `coincurve`; protocol logic and signature demonstration remain in Python.

Playwright serves the production build and covers the guided flow, advanced subcases and expected rejections, both networks, clipboard, QR decoding, PDF text/keys, language/theme persistence, timeout errors, stale requests, and a short real vanity search. Set `SP_PYTHON` to an alternative test-environment interpreter if needed. PR CI runs these checks without deployment secrets; the recipient-limit job has its own 60-minute timeout.

## Vercel Git deployment

The existing Git integration can deploy this project directly. Its install command installs Node dependencies and runs `scripts/build-vanity.py` before function packaging. The build command repeats the generator check and builds the frontend. Rust source is included in the upload; compiler outputs and virtual environments are excluded. The pinned Rust toolchain is bootstrapped when unavailable. The generator is compiled on Vercel’s Linux build image for its Linux runtime, self-tested, and bundled with a revision/checksum receipt. A failed generator build fails deployment.

After the local checks pass, merging into the configured production branch (`main` in this repository) triggers the normal Vercel deployment. No Vercel token or separate GitHub deployment workflow is required. Inspect `/api/health` after deployment for the source revision and `vanity_binary: true`.

To reproduce the source build locally on Linux x86_64, run `npm run vercel-build`. It generates ignored `api/bin/vanity` and `api/build-info.json` build artifacts. Other local platforms can use the usual native development build and `npm run build`.

## Optional preview delivery

Compiled binaries are ignored rather than committed. The **Verified preview** workflow is manually triggered from a reviewed repository branch. It first runs correctness CI, builds a static `x86_64-unknown-linux-musl` executable, and copies only required source and the fresh binary into an isolated `.preview-stage` directory. A manifest records the source revision and binary SHA-256. It never packages an existing developer binary.

Configure GitHub Actions secrets `VERCEL_TOKEN`, `VERCEL_ORG_ID`, and `VERCEL_PROJECT_ID` for the existing Vercel project. If preview protection is enabled, also configure `VERCEL_AUTOMATION_BYPASS_SECRET`. Then run **Verified preview**. It uses Vercel CLI 64.5.0 to pull preview settings, build, deploy with `--prebuilt`, and verify revision, runnable generator, reference cases, generation, and browser exports. The preview URL appears in the workflow summary. **It does not promote or deploy production.**

For a local packaging check after a musl build:

```sh
python3 scripts/prepare-preview.py \
  --binary native/vanity/target/x86_64-unknown-linux-musl/release/vanity \
  --output .preview-stage
python3 scripts/smoke-preview.py https://YOUR-PREVIEW --revision YOUR-COMMIT
```

Packaging normally requires a clean committed tree. `--allow-dirty` is only for local verification and marks the revision with `-dirty`. The optional preview workflow can reuse its verified prebuilt binary without installing Rust again; direct Git deployments build from source instead.

### Interactive privacy learning path

Start at `?view=privacy` for a bilingual, browser-only simulation of address reuse, fresh receiving addresses, and Silent Payments. Add up to six symbolic payments, inspect equal destinations, switch between an outside observer and Bob’s wallet, and simulate recognition with private scanning information. The model uses illustrative identifiers, never real addresses or keys; no API or blockchain connection is needed. Public amounts and privacy limitations remain visible. Restart resets the entire exercise.

The homepage links the privacy lab to the existing guided BIP-352 walkthrough and pinned reference explorer. The conceptual exercise is implemented in `src/features/privacy/`; protocol execution remains in the existing API and reference runner.

The privacy lab includes **Can you find Bob?**, an observer challenge with eight mixed outputs and three simulated Bob payments. Compare address reuse with distinct Silent Payments output keys, select suspects, optionally reveal a public receipt, and compare the hypothesis with the simulated wallet. The reveal reports correct, missed, and wrongly attributed payments rather than a privacy score. Ownership is local teaching data, not a security boundary; no cryptography is performed. Changing strategies clears guesses and clues while retaining the scenario. A new board or lab restart clears the exercise.

### Silent Payments Studio

The compact Explore page links to four workbenches: Payments, Addresses, Labels, and Scanning. Reference and Tools are the other primary navigation destinations. Existing privacy, walkthrough, reference, and generator APIs remain available. Generation and vanity are under `?view=tools`; the observer challenge is optional at `?view=privacy#observer`.

Studio links use `?view=studio&tool=payment&preset=default` and contain selection identifiers only. Experiments reset on reload, while language and theme persist. The workbench shell distinguishes conceptual previews from computed protocol results; technical evidence belongs under Inspect details.

The Payments workbench uses four curated eligible input cards and at most two payments to the public fixture receiver. Change an outpoint, reverse input order, change only the displayed amount, or mutate inputs after output derivation. Derivation and discovery use the real engine; proof of control signs a fixed synthetic message and verifies independently with libsecp256k1. Amounts are display metadata, not a transaction balance or fee model. No transaction is constructed or broadcast.

`GET /api/experiments` provides presets, public input summaries, samples, and pinned provenance. `POST /api/experiments/payment` accepts preset/network, one to four unique input IDs, recipient count (1–2), display amount, comparison, and action (`derive`, `scan`, `verify`). `POST /api/experiments/address` accepts a public address or uses the selected network’s sample. Unknown controls (including private keys/custom transactions) are rejected. Bodies are limited to 8 KiB and responses use `Cache-Control: no-store`. The inspector distinguishes malformed encoding/payloads, version 31 rejection, and versions 1–30 with validated keys and ignored extension bytes. Entered addresses are never placed in URLs, local storage, or application logs.

Browser tests start their own API/frontend on ports 5338/5183, keeping existing development services on 5328/5173 untouched. Override with `SP_TEST_API_PORT` and `SP_TEST_WEB_PORT`; both must be distinct ports from 1025–65535. `SP_API_PORT` changes Vite’s API proxy target for these isolated previews.

The Labels workbench maps Donations/Shop/Project to label indices 1/2/3 from the same public fixture receiver. `POST /api/experiments/labels` accepts a destination `label` and `known_labels` (unique subset of 1–3); the engine returns labeled addresses, output keys, and actual discovery. Friendly names are UI metadata. Change label 0 is handled by the protocol and is not offered as an external recipient label.

`POST /api/experiments/scan` accepts network and known labels for a fixed six-transaction batch: base payment, label-1 payment, unrelated output, no eligible inputs, unsupported witness input, and malformed witness. Transaction data passed to the scanner contains neither ownership hints nor sender private keys. Results distinguish found/no-match/skipped/rejected. Only the exact malformed-witness failure is displayed as an expected rejection; unrelated exceptions fail the request. The batch is synthetic public test data, not a blockchain connection.

### Visual experiment cards

The studio presents selectable coins, sender/receiver illustrations, wallet pockets, and expandable payment cards. One primary payment action advances through making a payment, finding it, and proving ownership. Visual fingerprints help compare actual output values; they are not addresses, QR codes, or checksums. Raw keys, version fields, signatures, and full JSON remain under Inspect details. Network and amount settings are expandable, with testnet still the default.

Transaction cards report actual found/no-match/skipped/rejected outcomes. “No match” does not assert that a payment belongs to someone else: an unknown label can prevent discovery. For the post-derivation mutation example, the visual comparison keeps the original output while showing discovery with changed inputs. Illustrations are conceptual and no real money moves. All card actions support keyboard use, English/Italian, both themes, and reduced motion.
