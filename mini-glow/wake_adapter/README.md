# Wake Adapter v0.1

Reads bridge_poller databases read-only and produces `WakeEvent` notifications. Standard library only:
no network, no credentials, no Bridge or Drive writes, no packet text, no transport.
Its only persistent write is its own checkpoint, `%LOCALAPPDATA%\MiniGlow\wake_adapter_checkpoint.json`,
advanced only from a validated delivery receipt (at-least-once).

Production activation (creating the checkpoint, choosing its high water and seed) needs Eric's approval.

## Rules

- **Identity is `packet_id + drive_file_id`.** Sequence numbers are order and anomaly evidence, never
  dedup authority and never proof of prior processing.
- **Routing:** `NEW` → GLOW. `ESCALATE` (including `LATE_BELOW_BOUNDARY`, `NEEDS_ERIC_ROW` and unhealthy
  runs) → ERIC. `OFFLINE_GAP` → ERIC, one summary event. `WAIT` is never delivered.
- **Authority is always `NOTIFICATION_ONLY`.** A WakeEvent authorises nothing.
- **STOP overrides delivery:** gate #1 before any read, gate #2 before events leave the adapter, gate #3 at
  the transport hand-over; commits are refused under STOP.
- **Checkpoint v2 carries `seeded_history`:** the identities present at or below `high_water` when it was
  initialised. A packet at or below `high_water` whose identity was not seeded escalates as
  `LATE_BELOW_BOUNDARY`. Without a seed nothing is history.
- **Poller mode changes identity.** The local Drive mirror mode (`--live`) records `drive_file_id` as
  `local:<file name>`; the Drive API mode (`--live-api`) records Drive file IDs. Switching poller mode
  requires a separately approved re-seed, otherwise every seeded packet escalates as late.
- One committer at a time, and every database that still has unconfirmed events is passed to each call.

## Commands

```
py -3.14 -B -m wake_adapter plan --db NAME.sqlite [--db ...] [--assume-high-water R2G-nnn --seed-db NAME.sqlite]
py -3.14 -B -m wake_adapter init --high-water R2G-nnn --seed-db NAME.sqlite     (needs Eric's approval)
```

Tests (run from `mini-glow`, also part of Mini Ray's `run_tests` task):

```
py -3.14 -X dev -W error::ResourceWarning -m unittest discover -s wake_adapter/tests -t .
```
