# Alcor

Alcor runs per-claimant checks for [Mizar](https://github.com/levarac/mizar) participation claims.

Mizar decides which mutual observations count as participation and settles claims in batch. Alcor handles the individual at join time: a join page the participant opens when joining the event, and a verification Worker that binds the attendee's event key to one World ID-verified person and publishes a signed credential list. Mizar's evaluator counts only credentialed keys, so one person running several devices cannot confirm their own observations. The claim itself happens later on Mizar's claim page.

## Status

Built during ETHGlobal Tokyo 2026 (hacking started 2026-09-25 21:00 JST). Work in progress.

## Pre-existing work

This repository was created after the hackathon started, and everything in it was written during the event. It builds on pre-existing work by the same team, which is not part of this repository:

- A mobile app that records and signs BLE proximity observations between attendees. The check runs on a web page; the app only adds a small entry point that signs a typed request with the attendee's event key, and that change is disclosed separately.
- An operator service and Solidity contracts on Sepolia that anchor the observation evidence Mizar evaluates.

## License

[MIT](LICENSE)
