# MG-001 draft proposal (reconstructed, v0.2)

**Status: DRAFT, not compared with the original.** The original MG-001 proposal was never received.
This page is rebuilt from Eric's instruction of 2026-10-02 and Glow's review. See `REVIEW-RESPONSE.md`.

## Purpose
Mini Glow is a worker agent: Glow's arms on Eric's Windows PC. Glow coordinates and reviews. Mini Glow
receives tasks, carries them out, preserves progress, returns evidence, and asks Glow for guidance when
stuck. Eric is the final authority. **In this pilot Mini Glow only tracks and gates work; it does not execute it.**

## Responsibilities in MG-001
1. Persistent task queue that survives restarts (no timers).
2. Receive tasks from Glow as packets that Eric relays by hand.
3. Check each task's declared actions against Eric's allowed list; pause on anything unknown.
4. Track state, notes, assumptions and evidence; produce help-request and return packets.
5. Keep reviewed memory (context, identity, permanent rules, permissions, upgrade history).
6. One database holds changes and audit events together; export JSONL and memory on demand.
7. Back up, verify and recover.

## Out of scope for MG-001
Browser control, unattended execution, automatic Glow connection, AI planning or summaries, executing
tasks, buying, sending messages, uploading anything before Eric confirms destinations.

## Acceptance checks (proposed) and the test that covers each
| # | Check | Test(s) |
|---|---|---|
| A1 | Queued task survives a restart | `test_state_survives_new_store_and_report_changes_nothing`; CLI tests run one process per command |
| A2 | Only valid status changes | `test_invalid_transitions` |
| A3 | Blocked task makes a help-request packet; resume records guidance | `test_manual_handoff_workflow` |
| A4 | Submit needs evidence; return packet lists actions, progress, evidence, assumptions | `test_priority_order_and_lifecycle`, `test_return_and_help_packets` |
| A5 | Evidence files hashed; tampering detected | `test_evidence_file_hash_and_tamper_detection` |
| A6 | Credentials, patient identifiers, SSN, card numbers refused, never stored or echoed | `test_sensitive_text_never_stored`, `test_guardrail_exit_code_and_no_leak` |
| A7 | Change and audit event are atomic; audit is append-only | `TestAudit` (5 tests) |
| A8 | Default deny; unknown pauses; keywords never grant | `TestPolicy`, `TestActionPolicy` |
| A9 | Buy/send unavailable even after Eric's approval | `test_buy_and_send_unavailable_even_after_approval` and related |
| A10 | Memory tiers: candidates, Eric-approved scope for Glow, Eric-only categories, sources, history | `TestMemoryTiers` |
| A11 | Backup, restore (with safety copy), archive, verify | `TestRecovery`, CLI `test_recover_backup_restore_and_exports` |

## Later stages (not built)
Layer 4 (AI interpretation, planning, summaries) and Layer 5 (agentic execution and automatic contact with Glow).
