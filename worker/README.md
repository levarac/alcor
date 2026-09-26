# Alcor human-check Worker

This Cloudflare Worker binds an event-scoped Beid key to one verified human at join time. The Worker is configured to serve the built join page and the API at https://alcor-human-check.levarac.workers.dev/. Deployment still requires a real D1 database and secret bindings.

## Local verification

```sh
cd worker
pnpm install --ignore-workspace --frozen-lockfile
pnpm --dir ../web install --ignore-workspace --frozen-lockfile
pnpm test
pnpm typecheck
pnpm exec wrangler d1 migrations apply alcor-human-check --local
pnpm exec wrangler deploy --dry-run
pnpm exec wrangler dev --local --var WORLD_APP_ID:app_LOCAL_TEST --var WORLD_RP_ID:rp_LOCAL_TEST
```

The test suite runs against a local Miniflare D1 database and an injected World verification client. `test/fixtures/world-success-v4.json` and `world-failures-v4.json` cover documented v4 shapes, invalid proof, wrong signal, duplicate nullifier, and expired local challenge. These are doc-shaped mocks, not captured live proofs. No test contacts the Developer Portal. `wrangler dev --local` starts without secrets, but `/rp-context` and `/verify` fail closed until their signing bindings are provided. Wrangler builds `web/dist` before local startup and deployment, then serves it through the `ASSETS` binding. API paths always run through the Worker; other GET/HEAD requests fall through to static assets, and missing files remain 404. This keeps relative API calls and callback `localStorage` on one origin. For Vite development, use `cd web && pnpm install --ignore-workspace && pnpm dev`; Vite proxies API requests to port 8787. The local IDs above are test placeholders, not Portal registrations. If the host hits a file-watcher limit, prefix the local dev command with `CHOKIDAR_USEPOLLING=1`; this does not change deployment configuration.

## HTTP contract

| Route | Input | Output |
| --- | --- | --- |
| `POST /challenge` | `{eventId}` | `{challenge, expiresAt}`; random 32 bytes, single use, 10 minutes |
| `POST /rp-context` | `{eventId}` | `{rp_id, nonce, created_at, expires_at, signature}` for IDKit 4 |
| `POST /bind` | `{eventId, eventKey, challenge, appSignature}` | `{signal}` after recovering the purpose `0x01` signer |
| `POST /verify` | `{eventId, eventKey, challenge, idkitResult}` | `{credential}` after World verification and the first verified nullifier wins |
| `GET /credentials?eventId=…` | query parameter | `{eventId, credentials:[…]}` |
| `GET /config?eventId=…` | query parameter | public IDKit configuration for the page |

The event ID is 32-byte hex; the event key is a compressed 33-byte secp256k1 public key. `/bind` computes `signal = keccak256(eventId || eventKeyAddress || challenge)` and returns those raw 32 bytes as hex. IDKit applies `hashSignal(signal)` to form `responses[0].signal_hash`; `/verify` looks up that exact bound challenge and compares the signal before contacting World. This preserves a valid proof from tab A even if the same key binds a later challenge in tab B. The purpose `0x01` message and digest must match [Mizar's golden vector](https://github.com/levarac/mizar/blob/main/docs/design/test-vectors/app-signature-v1.json). The test suite includes an exact copy at `test/fixtures/app-signature-v1.json`.

The World result is forwarded unchanged to `POST https://developer.world.org/api/v4/verify/{rp_id}`. This implementation accepts one World ID 4.0 `proof_of_human` uniqueness response, requires a successful matching result from World, checks action and environment, then inserts into D1 with unique `(event_id, nullifier_hash)` and `(event_id, event_key)` constraints. Nullifiers are normalized as 256-bit hex before comparison and storage. A failed proof never creates a credential.

Each credential contains `eventKey`, `eventKeyAddress`, `nullifierHash`, `verifiedAt` (UTC ISO-8601), `challenge`, `appSignature`, `proofDigest`, and `attestation`. `proofDigest` is SHA-256 over recursively sorted-key JSON of the complete IDKit result. The Ed25519 attestation signs raw UTF-8 `alcor/credential/v1`, one NUL byte, then recursively sorted-key JSON of the entry without `attestation`; there is no extra hash. `attestation` carries `algorithm`, `publicKey`, and `signature`. An evaluator must pin the expected service public key in its event parameters and compare it with the entry before verifying the signature. `test/fixtures/signed-credentials-v1.json` contains an exact deterministic signed `GET /credentials` response and a **public TEST seed only**. The seed must never be used for an event.

## ETHGlobal Tokyo deployment

The deployment uses a staging World app on a live Cloudflare Worker:

- Worker: `alcor-human-check`; page and callback origin: `https://alcor-human-check.levarac.workers.dev/`.
- D1 database: `alcor-human-check`; replace `REPLACE_WITH_PRODUCTION_D1_DATABASE_ID` in `wrangler.toml` with the ID returned by creation.
- Event: `0xccb8770a524f4145e04b3c97d8ffe2f7301ce65b4041d80e419bafdd803b2ee1` (`parallax-sepolia-20260926-demo`).
- Event window: `2026-09-26T05:30Z` to `2026-09-27T15:00Z`. The registry/evaluator owns this window; the Worker validates the event action and ten-minute challenges.
- Plain variables in `wrangler.toml`: `WORLD_ENV=staging`, `WORLD_ACTION=mizar-ccb8770a`. The older action in a local secrets file must not override this action.
- Public Ed25519 key for Mizar's `credentialsPublicKey`: `0xa5c6309b9109cb08f5a931984dcd97c182c780d8f940fb1e2abcca2e62f46057`.

The public key was derived from the maintainer-provided 32-byte seed. Only this public key is recorded here. The source variable `ALCOR_ATTESTATION_KEY` maps to the Worker's existing **`ATTESTATION_KEY`** binding, with a `0x` prefix. Do not upload it under a different binding name or use the public test seed.

| Worker binding | Delivery | Exposure |
| --- | --- | --- |
| `WORLD_ACTION`, `WORLD_ENV` | Plain vars in `wrangler.toml` | Public |
| `WORLD_APP_ID`, `WORLD_RP_ID` | `wrangler secret put` from local environment | Public identifiers returned by `/config`; their values are kept out of the repository |
| `WORLD_RP_SIGNING_KEY` | `wrangler secret put` via stdin | Secret; never log or commit |
| `ATTESTATION_KEY` | `ALCOR_ATTESTATION_KEY` via stdin | Secret Ed25519 seed; never log or commit |

Before deployment, confirm the Portal action `mizar-ccb8770a` is active for the staging app, allows the intended proof-of-human credential and one verification per human, and permits the HTTPS origin above where applicable. The mobile purpose `0x01` callback must use this same origin. Do not treat a successful local test or deployment as a real World ID verification.

### Create D1

Install both packages using the local-verification commands above. Run this from `worker/` in zsh. It creates a live database and must only be run by the deployment operator. Credentials stay inside a tracing-disabled subshell and are passed to Wrangler as command-scoped environment variables.

```zsh
(
  set +x
  set +v
  set -e
  source "$HOME/.config/zsh/secrets.zsh" >/dev/null 2>&1
  [ -n "${CLOUDFLARE_API_TOKEN_LEVARAC:-}" ] && echo SET || { echo UNSET; exit 1; }
  CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN_LEVARAC" \
    CLOUDFLARE_ACCOUNT_ID=3b81daf46f27d8d61d46559407b8a607 \
    pnpm exec wrangler d1 create alcor-human-check --update-config=false
)
```

Copy the returned `database_id` into `wrangler.toml`, replacing only `REPLACE_WITH_PRODUCTION_D1_DATABASE_ID`. Keep the `DB` binding and `alcor-human-check` database name. If a previous attempt created the database, obtain its existing ID instead of creating another database.

### Apply migrations, upload bindings, and deploy

Run from `worker/` after replacing the database ID. The first secret upload may prompt to create the named Worker if it does not exist yet; confirm only `alcor-human-check`. All four bindings must succeed before the final deployment. No secret values are passed as CLI arguments or written to temporary files.

```zsh
(
  set +x
  set +v
  set -e
  set -o pipefail
  source "$HOME/.config/zsh/secrets.zsh" >/dev/null 2>&1
  source "$HOME/Repository/Levarac/.env.local" >/dev/null 2>&1
  [ -n "${CLOUDFLARE_API_TOKEN_LEVARAC:-}" ] && echo SET || { echo UNSET; exit 1; }
  [ -n "${WORLD_APP_ID:-}" ] && echo SET || { echo UNSET; exit 1; }
  [ -n "${WORLD_RP_ID:-}" ] && echo SET || { echo UNSET; exit 1; }
  [ -n "${WORLD_RP_SIGNING_KEY:-}" ] && echo SET || { echo UNSET; exit 1; }
  [ -n "${ALCOR_ATTESTATION_KEY:-}" ] && echo SET || { echo UNSET; exit 1; }
  ALCOR_ATTESTATION_KEY="$ALCOR_ATTESTATION_KEY" node --input-type=module -e '
    import { createPrivateKey, createPublicKey } from "node:crypto";
    const seed = process.env.ALCOR_ATTESTATION_KEY.replace(/^0x/, "");
    if (!/^[0-9a-fA-F]{64}$/.test(seed)) throw new Error("Invalid seed format");
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed, "hex")]), format: "der", type: "pkcs8" });
    const publicKey = "0x" + createPublicKey(key).export({ format: "der", type: "spki" }).subarray(-32).toString("hex");
    if (publicKey !== "0xa5c6309b9109cb08f5a931984dcd97c182c780d8f940fb1e2abcca2e62f46057") throw new Error("Attestation public key mismatch");
  '
  cf() {
    CLOUDFLARE_API_TOKEN="$CLOUDFLARE_API_TOKEN_LEVARAC" \
      CLOUDFLARE_ACCOUNT_ID=3b81daf46f27d8d61d46559407b8a607 \
      pnpm exec wrangler "$@"
  }
  cf d1 migrations apply alcor-human-check --remote
  printf '%s' "$WORLD_APP_ID" | cf secret put WORLD_APP_ID
  printf '%s' "$WORLD_RP_ID" | cf secret put WORLD_RP_ID
  printf '%s' "$WORLD_RP_SIGNING_KEY" | cf secret put WORLD_RP_SIGNING_KEY
  printf '0x%s' "${ALCOR_ATTESTATION_KEY#0x}" | cf secret put ATTESTATION_KEY
  cf deploy
)
```

Retain the deployed version ID from Wrangler's output and the D1 ID from creation. The deployment command builds and uploads `web/dist` together with the Worker; no Pages project or token scope is needed. See [Cloudflare's asset binding documentation](https://developers.cloudflare.com/workers/static-assets/binding/) for the `run_worker_first` and `ASSETS.fetch` behavior.

### Live smoke checks

These are read-only requests. Run after deployment:

```sh
curl --fail-with-body -sS -i 'https://alcor-human-check.levarac.workers.dev/'
curl --fail-with-body -sS -i 'https://alcor-human-check.levarac.workers.dev/config?eventId=0xccb8770a524f4145e04b3c97d8ffe2f7301ce65b4041d80e419bafdd803b2ee1'
curl --fail-with-body -sS -i 'https://alcor-human-check.levarac.workers.dev/credentials?eventId=0xccb8770a524f4145e04b3c97d8ffe2f7301ce65b4041d80e419bafdd803b2ee1'
curl -sS -i 'https://alcor-human-check.levarac.workers.dev/config?eventId=invalid'
curl -sS -i 'https://alcor-human-check.levarac.workers.dev/missing.js'
```

Expect 200 HTML with the join page and new event ID at `/`; 200 JSON containing the configured `appId`, `rpId`, action `mizar-ccb8770a`, and environment `staging` at `/config`; and 200 JSON with the exact event ID and a `credentials` array at `/credentials` (initially empty). Invalid event config must return 400 JSON; missing assets must return 404. Open the join page in a browser and confirm its bundled JavaScript and CSS load. A real staging proof, mobile callback, credential publication after verification, and evaluator signature verification remain separate end-to-end checks.

## World source references

- [IDKit 4 integration guide](https://docs.world.org/world-id/idkit/integrate): `rp_context` fields, staging simulator, World ID 4 uniqueness response shape, unchanged payload forwarding, and backend nullifier storage.
- [IDKit credential presets](https://docs.world.org/world-id/idkit/credentials): `proofOfHuman({signal})` and `allow_legacy_proofs`.
- [World v4 verify API](https://docs.world.org/api-reference/developer-portal/verify): `POST /api/v4/verify/{rp_id}` and `success`, `results`, `action`, `nullifier`, `environment` response fields.
- [IDKit core hashing implementation](https://github.com/worldcoin/idkit/blob/main/js/packages/core/src/lib/hashing.ts): `hashSignal` computes `keccak256(signal bytes) >> 8`.
- [IDKit core JavaScript README](https://github.com/worldcoin/idkit/blob/main/js/packages/core/README.md): browser API and backend RP signature generation.
