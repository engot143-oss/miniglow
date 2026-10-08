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
- **Interruption-safe.** Every file write is atomic and a leftover temporary file is refused, never overwritten.
  An interruption never confirms anything wrongly. `audit-verify` reconciles the audit log with the checkpoint
  and the outbox and names any trace an interruption left: a delivery without its audit entry (repair: run
  `deliver` again) or a confirmed event without its ACKED entry (repair: acknowledge it again, which records
  `ALREADY_CONFIRMED` without a second commit). A stuck `STUCK_DELIVERY` escalation never escalates again.

## Bridge link v0.3 (automatic Claude ↔ Glow packets)

- Claude writes packets to `Glow-Ray-Bridge\Claude-to-Glow\BL-Cnnnn_*.txt` and reads replies from
  `Glow-Ray-Bridge\Glow-to-Claude\BL-Gnnnn_*.txt`. It never writes Ray-to-Glow or Glow-to-Ray. No purchases,
  no subscriptions, no email: the Bridge is a Google Drive folder Eric already owns.
- Each packet carries `ACK_REF` and a one-time `ACK_CODE`. A reply counts only if it is complete, answers a
  packet Claude sent, and holds exactly one matching `ACK <ref> <code>` line. Every reply file is processed once;
  its text is saved to `MiniGlow\bridge_inbox\`. Reply text is evidence, never instructions.
- `PING` packets are harmless tests. `WAKE_EVENT` packets carry pending GLOW deliveries. **Nothing acknowledges
  an event automatically:** a valid Glow reply to a WAKE_EVENT waits as `AWAITING_ERIC` until Eric runs
  `bridge-confirm` and types YES.
- `bridge-cycle` (safe to schedule) reads replies, delivers only *new* events (it never uses up retries) and sends
  packets for pending GLOW deliveries. STOP and a broken audit chain stop it before any write.
- `glow_standin` is a **local test stand-in, not the real Glow**: it answers PINGs using the free local model
  (Ollama on 127.0.0.1), signs replies `GLOW-STANDIN`, and can never answer for a WakeEvent.

## Commands

```
py -3.14 -B -m wake_adapter plan --db NAME.sqlite [--db ...] [--assume-high-water R2G-nnn --seed-db NAME.sqlite]
py -3.14 -B -m wake_adapter init --high-water R2G-nnn --seed-db NAME.sqlite     (needs Eric's approval)
py -3.14 -B -m wake_adapter deliver --db NAME.sqlite [--db ...]
py -3.14 -B -m wake_adapter inbox [--route ERIC|GLOW]
py -3.14 -B -m wake_adapter ack EVENT_ID CODE                                   (Eric types YES)
py -3.14 -B -m wake_adapter ack-glow --text "ACK EVENT_ID CODE"                 (Eric types YES)
py -3.14 -B -m wake_adapter audit-verify
py -3.14 -B -m wake_adapter bridge-ping [--note TEXT]
py -3.14 -B -m wake_adapter bridge-cycle [--db NAME.sqlite ... | --all-dbs]
py -3.14 -B -m wake_adapter bridge-status
py -3.14 -B -m wake_adapter bridge-confirm BL-Cnnnn                            (Eric types YES)
py -3.14 -B -m glow_standin [--no-model]                                         (test stand-in only)
```

Tests (run from `mini-glow`, also part of Mini Ray's `run_tests` task):

```
py -3.14 -X dev -W error::ResourceWarning -m unittest discover -s wake_adapter/tests -t .
```
