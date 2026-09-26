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

## Pre-existing work

This repository was created after the hackathon started, and everything in it was written during the event. It builds on pre-existing work by the same team, which is not part of this repository:

- **[Beid](https://github.com/levarac/beid)**, the attendee app that records and signs BLE proximity observations. Its repository is public. The Alcor check runs on a web page; the typed signing entry point on [Beid's `demo/ethtokyo-two-iphone` branch](https://github.com/levarac/beid/tree/demo/ethtokyo-two-iphone) is a hackathon integration change inside the pre-existing app.
- **Parallax**, the protocol whose operator service and Solidity contracts on Sepolia anchor the observation evidence Mizar evaluates. Its repository is private.
- **[Barnard](https://github.com/levarac/barnard)**, the public BLE sensing library and SDK used by Beid.

## License

[MIT](LICENSE)
