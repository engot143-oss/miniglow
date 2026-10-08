# Wake Adapter and Wake Transport v0.2

Reads bridge_poller databases read-only and produces `WakeEvent` notifications. The v0.2 transport delivers
them to a **local outbox** on this PC. Standard library only: no network, no credentials, no Bridge or Drive
writes, no packet text, nothing sent off this PC.

Writes, all in `%LOCALAPPDATA%\MiniGlow`: the checkpoint `wake_adapter_checkpoint.json`, the outbox
`outbox\<ERIC|GLOW>\<event_id>.json`, and the audit log `wake_transport_audit.jsonl`.

Production activation (creating the checkpoint, choosing its high water and seed) needs Eric's approval.

## Rules

- **Identity is `packet_id + drive_file_id`.** Sequence numbers are order and anomaly evidence, never
  dedup authority and never proof of prior processing.
- **Routing:** `NEW` → GLOW. `ESCALATE` (including `LATE_BELOW_BOUNDARY`, `NEEDS_ERIC_ROW`, `STUCK_DELIVERY`
  and unhealthy runs) → ERIC. `OFFLINE_GAP` → ERIC, one summary event. `WAIT` is never delivered.
- **Authority is always `NOTIFICATION_ONLY`.** A WakeEvent authorises nothing; an acknowledgment only records
  that the recipient saw it.
- **STOP overrides everything:** gate #1 before any read, #2 before events leave the adapter, #3 before any
  outbox write, #4 before an acknowledgment is accepted, #5 before the checkpoint commit.
- **Checkpoint v2 carries `seeded_history`:** the identities present at or below `high_water` when it was
  initialised. A packet at or below `high_water` whose identity was not seeded escalates as
  `LATE_BELOW_BOUNDARY`. Without a seed nothing is history.
- **Poller mode changes identity.** The local Drive mirror mode (`--live`) records `drive_file_id` as
  `local:<file name>`; the Drive API mode (`--live-api`) records Drive file IDs. Switching poller mode
  requires a separately approved re-seed, otherwise every seeded packet escalates as late.
- One committer at a time, and every database that still has unconfirmed events is passed to each call.

## Transport v0.2 (local outbox)

- **Delivery is not acknowledgment.** `deliver` writes each unconfirmed event with a fresh 8-character
  delivery code. The checkpoint does not change.
- **Explicit acknowledgment, one event at a time.** The ack must quote the event_id and the *current* code,
  then Eric types `YES`. Eric acknowledges ERIC events (`ack`). Glow acknowledges GLOW events with one line
  `ACK <event_id> <code>` in its reply, which Eric enters (`ack-glow`). Routes cannot cross. No batch acks.
- **At-least-once with bounded retries.** Each `deliver` run re-delivers unacknowledged events with a new code
  (the old code stops working), up to 3 attempts. Then the event is marked STUCK and one `STUCK_DELIVERY`
  escalation goes to Eric. A stuck event can still be acknowledged. Retries happen only when someone runs
  `deliver`: no background service, no schedule.
- **Tamper-evident.** Each outbox record is rebuilt and checked against its event_id. The audit log is
  hash-chained; a broken chain refuses all further delivery and acknowledgment. Codes are logged only as hashes.

## Commands

```
py -3.14 -B -m wake_adapter plan --db NAME.sqlite [--db ...] [--assume-high-water R2G-nnn --seed-db NAME.sqlite]
py -3.14 -B -m wake_adapter init --high-water R2G-nnn --seed-db NAME.sqlite     (needs Eric's approval)
py -3.14 -B -m wake_adapter deliver --db NAME.sqlite [--db ...]
py -3.14 -B -m wake_adapter inbox [--route ERIC|GLOW]
py -3.14 -B -m wake_adapter ack EVENT_ID CODE                                   (Eric types YES)
py -3.14 -B -m wake_adapter ack-glow --text "ACK EVENT_ID CODE"                 (Eric types YES)
py -3.14 -B -m wake_adapter audit-verify
```

Tests (run from `mini-glow`, also part of Mini Ray's `run_tests` task):

```
py -3.14 -X dev -W error::ResourceWarning -m unittest discover -s wake_adapter/tests -t .
```
