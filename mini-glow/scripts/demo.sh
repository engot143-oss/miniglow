#!/usr/bin/env bash
# Linux/macOS version of the demo (this is the one that was actually run for the review).
# Run from the mini-glow folder:  bash scripts/demo.sh
set -u
export MINI_GLOW_HOME="${TMPDIR:-/tmp}/mini_glow_demo"
rm -rf "$MINI_GLOW_HOME"
PY="${PYTHON:-python3}"
mg() { echo; echo "\$ mg $*"; "$PY" -m mini_glow "$@"; echo "[exit code $?]"; }
step() { echo; echo "=================== $* ==================="; }

step "1. Set up"
mg init

step "2. Eric allows what Mini Glow may touch (default is deny)"
mg policy propose read_file C:/Users/Eric/practice_files --source "Eric, demo"
mg proposal approve 6 --by eric
mg policy propose write_file C:/Users/Eric/practice_files/out --source "Eric, demo"
mg proposal approve 7 --by eric

step "3. Glow's task arrives (you relay it). Actions are checked against Eric's list"
mg add examples/task_from_glow.md
mg start

step "4. Authorize individual actions (nothing is executed; this is the gate)"
mg authorize MG-T-0001 read_file C:/Users/Eric/practice_files/a.txt
mg authorize MG-T-0001 read_file C:/Users/Eric/Documents
mg authorize MG-T-0001 send_message team
mg authorize MG-T-0001 organize_files C:/x

step "5. Progress, stuck, ask Glow, resume"
mg note MG-T-0001 "Opened the practice folder and listed its files"
mg block MG-T-0001 "Which file-name style should I use?" --tried "Checked the folder for examples"
mg resume MG-T-0001 "Use YYYY-MM-DD_name.ext"

step "6. Evidence, submit, return packet for Glow"
mg evidence MG-T-0001 --text "checklist.txt created with 6 numbered steps"
mg submit MG-T-0001 "Checklist drafted and saved"
mg accept MG-T-0001 --by glow --comment "Looks good"

step "7. Buy/send wording: flagged, paused, and Eric's approval cannot activate it"
mg add examples/task_needs_approval.md
mg decide MG-T-0002 --by eric --decision approve
mg start MG-T-0002
mg policy propose send_message team --source "demo"

step "8. Unknown action pauses for clarification"
mg add examples/task_unknown_action.md
mg clarify MG-T-0003 --by glow --actions "read_file: C:/Users/Eric/practice_files"

step "9. Reviewed memory: worker candidate -> Eric scope -> Glow approves"
mg memory propose project_context "Practice folder holds 12 files" --source "MG-T-0001 evidence" --scope mini-glow
mg proposals
mg proposal approve 8 --by glow
mg scope allow mini-glow --by eric
mg proposal approve 8 --by glow
mg memory show project_context

step "10. Restart check, health, backup, audit export"
mg recover
mg verify
mg backup --zip
mg export-log
echo; echo "Audit trail for MG-T-0001:"; mg log --task MG-T-0001
