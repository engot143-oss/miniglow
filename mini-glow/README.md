# Mini Glow - MG-001 pilot (v0.2.0)

A **task-management foundation** for Mini Glow, Glow's worker on Eric's Windows PC. It keeps a
persistent task queue, tracks progress and evidence, produces handoff packets, gates actions against
Eric's allowed list, and keeps reviewed project memory.

**What it is not:** it does not execute tasks, call any AI, or contact Glow. AI execution and automatic
contact with Glow are future stages. **You relay all messages between Claude, Glow and Mini Glow by hand.**

**Windows status: NOT TESTED ON WINDOWS.** Everything here was run on Linux with Python 3.13.15.
`mg.bat` and `scripts\demo.ps1` are unrun on Windows. Treat the first Windows run as a test and report differences.

Python 3.10+ and nothing else (standard library only).

## Windows setup
1. Install Python from python.org (tick "Add python.exe to PATH").
2. Unzip, open PowerShell in the `mini-glow` folder, check: `python --version`
3. Optional data location: `$env:MINI_GLOW_HOME = "C:\Users\<you>\MiniGlowData"` (default `.\mini_glow_data`)
4. `python -m mini_glow init`
5. Tests: `python -m unittest discover -s tests -v`
6. Guided demo: `powershell -ExecutionPolicy Bypass -File scripts\demo.ps1`

## How it works (one picture)
```
Glow packet --(you paste)--> add --> actions checked against Eric's allowed list
                                        |-- all allowed -----------> queued --> start --> in_progress
                                        |-- unknown / not allowed -> needs_clarification --(Glow/Eric clarify)--> queued
in_progress --block--> blocked --resume--> in_progress
in_progress --submit (needs evidence)--> awaiting_review --accept--> done   (or --rework--> in_progress)
```

## The rules, in plain words
| Rule | How it works |
|---|---|
| One source of truth | One SQLite database. Each change and its audit event are saved in the **same transaction**: both happen or neither does. Audit events cannot be edited or deleted (database triggers). |
| JSONL and memory files are exports | `export-log` writes JSONL from the database. `memory\*.md` are generated from the database; `verify` flags them if they drift. |
| Default deny | Mini Glow may touch nothing until Eric allows a target (`policy propose` then `proposal approve --by eric`). |
| Explicit categories | Available: `read_file`, `write_file`, `draft_text` (targets must be on Eric's list). Unavailable in this pilot: `buy`, `send_message`, `browser_control`, `unattended_run`, `run_program`, `network_request`. |
| Unknown pauses | A task with no `ACTIONS`, an unknown category, or a missing target becomes `needs_clarification`. |
| Keywords flag, never grant | Wording like "buy" or "send an email" only flags the task and requires Eric's recorded decision. It grants nothing. |
| Buy and send stay off | Eric's `decide --decision approve` records his decision only. It cannot activate buy/send, and no permission can even be proposed for them. |
| Memory tiers | Worker observations are **candidates** until reviewed. Glow may approve `project_context` / `task_context` only inside a scope Eric approved. Eric approves `identity`, `permanent_rules`, permissions/access and scopes. Every entry needs a source; changes supersede, never overwrite. |
| Limits | `--by eric` and `--by glow` are honor-system labels, not logins. Pattern checks for secrets and patient data reduce accidents; they are not a guarantee. |

## Packet format (Glow -> Mini Glow)
`GOAL:` and `YOUR JOB:` required. Optional: `TITLE`, `REF`, `PRIORITY` (1-9), `CONTEXT`, `INPUT`,
`ACTIONS`, `RULES`, `OUTPUT FORMAT`, `DONE WHEN`, `NEXT STOP`. `ACTIONS` lines look like `category: target`.
See `examples\`.

## Commands
`init add list show decide clarify start authorize note evidence block resume submit packet accept rework
fail cancel retry log export-log export-memory recover verify backup snapshots restore`
plus `memory`, `policy`, `scope`, `proposals`, `proposal`. Use `python -m mini_glow <command> -h`.
Exit codes: 0 ok, 2 error, 3 guardrail block, 4 authorize DENY, 5 authorize PAUSE.

## Where things are stored (under the data folder)
| Path | What |
|---|---|
| `mini_glow.db` | tasks, actions, events, evidence, proposals, permissions, scopes |
| `memory\*.md` | generated memory files |
| `exports\events.jsonl` | generated audit export |
| `evidence\<task>\` | copied evidence files (SHA-256 recorded in the database) |
| `handoffs\outbox\` | packets to relay to Glow |
| `backups\` | snapshots and zip archives |

## Known limitations
- Not run on Windows; Python 3.13 only.
- Tracks and gates work; does not execute it. `authorize` is a gate a later layer must call.
- `memory\*.md` are written just after the database commit; if that write fails, `verify` reports it and
  `export-memory` fixes it. (The database itself has no such gap.)
- A copied evidence file is removed if its database write rolls back; a hard crash in between could leave an
  orphan file that no record points to (harmless; not detected by `verify`).
- Approver names are labels, not authentication. Secret/patient detection is pattern-based.
- Original MG-001 proposal not received, so acceptance checks are not compared against it.
  See `docs\REVIEW-RESPONSE.md`.
