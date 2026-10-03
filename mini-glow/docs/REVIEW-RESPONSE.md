# Response to Glow's preliminary review (v0.1.0 -> v0.2.0)

Status key: **Done and tested** = implemented and covered by a test that was run. **Not done** = say why.

## Item 1 - Compare the original proposal with the reconstructed draft
**Not done. Blocked: the original proposal was never received.**
It did not arrive with the first request, and a search of the workspace this session found no file.
A comparison written without it would be invented, so none is provided.
What exists instead:
- `docs/MG-001-proposal-draft.md` is the reconstructed draft (from Eric's message only), with acceptance
  checks now mapped to real tests.
- The table below compares the draft against **Glow's seven review points**. That is not the original.
- To finish: Eric attaches the original, and the comparison table at the bottom of this file gets filled in.

## Item 2 - Keep SQLite; store task changes and audit events in one transaction
**Done and tested.**
- Every mutating method writes the change and its audit event in one `BEGIN IMMEDIATE ... COMMIT`.
- The separate `logs/events.jsonl` write is gone. JSONL is now an export (`export-log`).
- `events` is append-only (triggers refuse UPDATE/DELETE).
- Tests: `test_task_change_and_event_are_one_transaction` (an injected failure while logging rolls back the
  status change too), `test_every_change_writes_an_event`, `test_events_are_append_only`,
  `test_jsonl_is_an_export_of_the_database`, `test_no_separate_log_file_in_normal_operation`.
- Remaining gap, disclosed: generated `memory/*.md` files are written after the commit. `verify` detects
  drift; `export-memory` repairs it. The database is never ahead of or behind its own audit trail.

## Item 3 - Explicit action categories and allowed targets; unknown pauses
**Done and tested.**
- Categories in `policy.py`. Available: `read_file`, `write_file`, `draft_text`. Unavailable: `buy`,
  `send_message`, `browser_control`, `unattended_run`, `run_program`, `network_request`.
- Allowed targets come only from Eric-approved entries; default is deny. Targets are normalized
  (slashes, case); `..` is rejected; sibling folders like `in` vs `inbox` do not match.
- Keywords only set a flag (`flagged`). They never grant permission.
- Unknown category, no target, or no `ACTIONS` at all -> `needs_clarification` (pause).
- `authorize` checks policy first (deny/pause), then requires the action to be declared on the task.
- Tests: `TestPolicy.test_decisions`, `test_unknown_action_pauses_and_clarify_fixes_it`,
  `test_task_without_actions_pauses`, `test_keywords_flag_but_never_grant`,
  `test_authorize_decisions_are_audited`, `test_revoked_permission_pauses_at_start`.
- A bug found while testing this: the first version of `authorize` returned PAUSE (not DENY) for undeclared
  `send_message` and for path traversal. Fixed by checking policy first.

## Item 4 - Buy and send unavailable, even after a test approval
**Done and tested.**
- `decide --decision approve` records Eric's decision only. It does not change any action's availability.
- `buy` / `send_message` cannot be proposed as permissions, are denied at task intake and at `authorize`,
  and a task that declares them cannot start no matter what Eric records.
- Tests: `test_buy_and_send_unavailable_even_after_approval`,
  `test_buy_send_denied_at_authorize_even_if_declared_and_started`, `test_flag_decision_records_only`,
  CLI `test_buy_send_cannot_be_activated_by_approval`, `test_authorize_exit_codes`.

## Item 5 - Memory authority tiers
**Done and tested, with one assumption for Glow and Eric to confirm.**
- Worker observations are candidates (proposals) until reviewed; they are not memory.
- Glow may approve `project_context` and `task_context` entries **only inside a scope Eric has approved**
  (`scope allow NAME --by eric`). Every entry needs a source and a scope; changes supersede earlier entries
  and the history stays visible; rejected candidates are kept in `upgrade_history`.
- Eric alone approves `identity`, `permanent_rules`, permissions/access, scopes, and revocations.
- Tests: `TestMemoryTiers` (9 tests) and CLI `test_memory_tiers_via_cli`.
- **Assumption:** "within Eric's approved scope" is implemented as named scopes Eric approves. No scope is
  approved by default, so until Eric sets one, only Eric can approve context entries.
- **Seed entries:** the database starts with five entries drawn from Eric's 2026-10-02 instruction
  (identity and permanent rules), labelled as seeds with that source. Eric should confirm or change them.

## Item 6 - Keep limitations explicit
**Done.** README states: task-management foundation; no execution, no AI, no automatic Glow contact.

## Item 7 - Deliverables
Runnable ZIP, SHA-256, full source, tests, actual outputs (`docs/demo-output-linux.txt` and the test run
in the cover message), and this comparison. **Windows remains untested.**
GitHub and Drive destinations are unconfirmed; nothing has been uploaded.

## Comparison against the original proposal (to complete when it is received)
| Original requirement | In reconstructed draft? | Implemented in v0.2.0? | Verified by |
|---|---|---|---|
| (original not received) | - | - | - |
