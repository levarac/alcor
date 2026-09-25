# Alcor human-check Worker

This Cloudflare Worker binds an event-scoped Beid key to one verified human at join time. It does not deploy itself, register a World app, or accept a live proof with the example bindings in `wrangler.toml`.

## Local verification

```sh
cd worker
pnpm install
pnpm test
pnpm typecheck
pnpm wrangler d1 migrations apply alcor-human-check-local --local
pnpm wrangler dev --local
```

The test suite runs against a local Miniflare D1 database and an injected World verification client. `test/fixtures/world-success-v4.json` and `world-failures-v4.json` cover documented v4 shapes, invalid proof, wrong signal, duplicate nullifier, and expired local challenge. These are doc-shaped mocks, not captured live proofs. No test contacts the Developer Portal. `wrangler dev --local` starts without secrets, but `/rp-context` and `/verify` fail closed until their signing bindings are provided. Local browser development uses `cd web && pnpm install && pnpm dev`; Vite proxies API requests to port 8787. For a static deployment, serve `web/dist` and the Worker routes from the same HTTPS origin so the app callback can recover its `localStorage` state. No static deployment is configured here.

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

## Maintainer setup in the World Developer Portal

No Portal registration has been performed. The maintainer must:

1. Create a staging World ID app in the [Developer Portal](https://developer.world.org/) and enable/register World ID 4.0 as a relying party. Record the resulting `app_id`, `rp_id`, and RP `signing_key`. For a later production app, perform the equivalent production registration separately.
2. Register the one-time action `mizar-<first 8 lowercase hex digits of eventId>` for the intended event, for example `mizar-996ab4d7` for the demo event. Confirm it is active and uses the intended proof-of-human credential and one verification per human. Keep the action identical in IDKit, `WORLD_ACTION`, and the Worker check.
3. Configure the permitted HTTPS page/callback origin in the Portal if required by the app registration. Configure the Beid app's compiled-in purpose `0x01` callback to that same origin. The callback URL is an open decision in Mizar D9; it must be settled before a real join flow.
4. Replace the obviously fake `WORLD_APP_ID`, `WORLD_RP_ID`, and `WORLD_ACTION` examples in deployment bindings. Set `WORLD_ENV=staging` for simulator testing, or `production` only with the production registration. Set `WORLD_RP_SIGNING_KEY` as a secret binding with the Portal's RP signing key. Set `ATTESTATION_KEY` as a separate 32-byte Ed25519 seed secret, publish its derived public key to the evaluator's `credentialsPublicKey` parameter, and retain the private seed outside the repository. Never use the test seed.
5. Apply `migrations/0001_initial.sql` to the selected D1 database, then use the [World simulator](https://simulator.worldcoin.org/) for a staging end-to-end check. Recheck the `/config` action, RP context, callback origin, and pinned attestation public key before any production use.

The example `wrangler.toml` uses fake IDs, a fake unregistered action, and an all-zero local D1 UUID. It contains no signing keys or credentials. `/rp-context` and `/verify` require their secret bindings at runtime.

## World source references

- [IDKit 4 integration guide](https://docs.world.org/world-id/idkit/integrate): `rp_context` fields, staging simulator, World ID 4 uniqueness response shape, unchanged payload forwarding, and backend nullifier storage.
- [IDKit credential presets](https://docs.world.org/world-id/idkit/credentials): `proofOfHuman({signal})` and `allow_legacy_proofs`.
- [World v4 verify API](https://docs.world.org/api-reference/developer-portal/verify): `POST /api/v4/verify/{rp_id}` and `success`, `results`, `action`, `nullifier`, `environment` response fields.
- [IDKit core hashing implementation](https://github.com/worldcoin/idkit/blob/main/js/packages/core/src/lib/hashing.ts): `hashSignal` computes `keccak256(signal bytes) >> 8`.
- [IDKit core JavaScript README](https://github.com/worldcoin/idkit/blob/main/js/packages/core/README.md): browser API and backend RP signature generation.
