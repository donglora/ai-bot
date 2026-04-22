# Changelog

## 1.0.0 — 2026-04-22

Initial public release. Orac is a MeshCore chatbot that uses the
`donglora` client to bridge a LoRa dongle to an Anthropic model.

### Added

- `BotRuntime` orchestrating IO, worker, and log threads against a
  `donglora.Dongle` instance.
- ADVERT scheduler with IQR-trimmed mean position derived from heard
  repeater adverts.
- Typed `TxQueue` with retry / ack tracking against MeshCore message
  IDs.
- DM reply pipeline that calls Claude off the IO loop and enqueues
  reply packets at the right priority.
- Structured JSONL event log at `~/.donglora/orac-events.jsonl`.
- `just run` / `just check` / `just events` developer ergonomics.
- `donglora>=1.0.0,<2.0.0` declared as the registry dep; local dev
  uses the `[tool.uv.sources]` editable-path override.

### Notes

- Not published to PyPI. Installed from a local checkout only; this
  1.0.0 tag captures the point at which the bot runs against the
  Protocol v2 stack (`donglora` 1.0 / `donglora-mux` 1.0 /
  `donglora-protocol` 1.0).
