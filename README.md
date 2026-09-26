# Alcor

Alcor is the human-check service of **Levarac**, built at ETHGlobal Tokyo 2026. Levarac is the team and project name used for the event and its Showcase listing. Levarac comprises:

- **Parallax** — protocol for signed BLE observations and anchored evidence; pre-existing before the hackathon; private repository.
- **[Beid](https://github.com/levarac/beid)** — attendee app that records and signs BLE observations; pre-existing before the hackathon; public repository.
- **[Barnard](https://github.com/levarac/barnard)** — BLE sensing library and SDK; pre-existing before the hackathon; public repository.
- **[Mizar](https://github.com/levarac/mizar)** — participation-rule evaluator and EAS claim system; built at ETHGlobal Tokyo 2026; public repository.
- **[Alcor](https://github.com/levarac/alcor)** — human-check service and join page; built at ETHGlobal Tokyo 2026; public repository.

Mizar evaluates mutual observations against a published participation rule and batches the results into a snapshot root. Alcor handles the individual at join time: a join page the participant opens when joining the event, and a verification service that binds the attendee's Beid event key to one World ID-verified person and publishes a signed credential list. Mizar's evaluator counts only Alcor-credentialed keys, with one event key per verified person. Each claim happens individually later on Mizar's claim page.

## Join page

The join page keeps each pending check in `localStorage`, not `sessionStorage`, under a key built from a random per-check state value. A callback is accepted only if its state matches a pending entry in this browser, and the callback fragment is cleared before that check. Successful checks remove their entries; abandoned checks remain until the browser's local storage is cleared.

## Status

Built during ETHGlobal Tokyo 2026 (hacking started 2026-09-25 21:00 JST). Work in progress.

**Known limitation (World ID staging):** the World ID Simulator generates every World ID 4.0 staging proof from one server-side identity, whichever test identity is selected in the browser. Since [worldcoin/simulator#236](https://github.com/worldcoin/simulator/pull/236), its sidecar picks the first configured identity that can satisfy the request and ignores the selected one ([`sidecar/src/routes.rs`](https://github.com/worldcoin/simulator/blob/9fdc0724704d660893a384b1259c469ef57db583/sidecar/src/routes.rs)). Every staging proof for an action therefore carries the same nullifier, so a staging event can hold only one credential. On 2026-09-27, human checks using new Simulator identities, browsers and devices all verified at World and were then rejected with `409 credential_already_exists` for this reason. A live run with several people needs production World ID and real World App users.

**Staging compatibility mode (World ID 3.0 proofs):** for the demo, the staging deployment accepts World ID 3.0 legacy proofs requested through IDKit 4's legacy compatibility path (`orbLegacy` preset with `allow_legacy_proofs`). The verify API is still World's v4 endpoint, but the proof protocol is World ID 3.0, and the World ID Simulator generates those proofs in the browser from the selected test identity, so distinct Simulator identities give distinct nullifiers. The proof stays bound to the event, event key and challenge through the same signal. The mode is on only when `WORLD_ENV` is `staging` and `WORLD_LEGACY_STAGING` is `on`; the Worker rejects legacy proofs in production. It does not demonstrate native World ID 4.0 multi-identity behavior or real humans. Production uses native World ID 4.0 proofs.

## Pre-existing work

This repository was created after the hackathon started, and everything in it was written during the event. It builds on pre-existing work by the same team, which is not part of this repository:

- **[Beid](https://github.com/levarac/beid)**, the attendee app that records and signs BLE proximity observations. Its repository is public. The Alcor check runs on a web page. The hackathon changes to Beid, a typed event-key signing entry point and a two-iPhone demo configuration, are on [Beid's `demo/ethtokyo-two-iphone` branch](https://github.com/levarac/beid/tree/demo/ethtokyo-two-iphone) at head [5a848fb](https://github.com/levarac/beid/commit/5a848fb1d07bae01ec5a9b5550f0e13bca6fdf6e).
- **Parallax**, the protocol whose operator service and Solidity contracts on Sepolia anchor the observation evidence Mizar evaluates. Its repository is private.
- **[Barnard](https://github.com/levarac/barnard)**, the public BLE sensing library and SDK used by Beid.

## License

[MIT](LICENSE)
