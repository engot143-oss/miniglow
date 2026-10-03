# Mini Glow demo (Windows PowerShell). Run from the mini-glow folder:
#   powershell -ExecutionPolicy Bypass -File scripts\demo.ps1
# NOT YET RUN ON WINDOWS. The Linux version, scripts/demo.sh, is the one that was run
# (its real output is in docs/demo-output-linux.txt). Report any difference to Glow.
# Uses a throwaway data folder so it never touches your real queue.
# Note: proposal numbers 6, 7, 8 below assume a fresh folder (seed entries use 1-5).

$env:MINI_GLOW_HOME = Join-Path $env:TEMP "mini_glow_demo"
if (Test-Path $env:MINI_GLOW_HOME) { Remove-Item -Recurse -Force $env:MINI_GLOW_HOME }

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }
function mg { Write-Host "`n> mg $args" -ForegroundColor DarkGray; python -m mini_glow @args; Write-Host "[exit code $LASTEXITCODE]" -ForegroundColor DarkGray }

Step "1. Set up"
mg init

Step "2. Eric allows what Mini Glow may touch (default is deny)"
mg policy propose read_file C:/Users/Eric/practice_files --source "Eric, demo"
mg proposal approve 6 --by eric
mg policy propose write_file C:/Users/Eric/practice_files/out --source "Eric, demo"
mg proposal approve 7 --by eric

Step "3. Glow's task arrives (you relay it)"
mg add examples\task_from_glow.md
mg start

Step "4. Authorize individual actions (nothing is executed; this is the gate)"
mg authorize MG-T-0001 read_file C:/Users/Eric/practice_files/a.txt
mg authorize MG-T-0001 read_file C:/Users/Eric/Documents
mg authorize MG-T-0001 send_message team
mg authorize MG-T-0001 organize_files C:/x

Step "5. Progress, stuck, ask Glow, resume"
mg note MG-T-0001 "Opened the practice folder and listed its files"
mg block MG-T-0001 "Which file-name style should I use?" --tried "Checked the folder for examples"
mg resume MG-T-0001 "Use YYYY-MM-DD_name.ext"

Step "6. Evidence, submit, return packet for Glow"
mg evidence MG-T-0001 --text "checklist.txt created with 6 numbered steps"
mg submit MG-T-0001 "Checklist drafted and saved"
mg accept MG-T-0001 --by glow --comment "Looks good"

Step "7. Buy/send wording: flagged, paused, and Eric's approval cannot activate it"
mg add examples\task_needs_approval.md
mg decide MG-T-0002 --by eric --decision approve
mg start MG-T-0002
mg policy propose send_message team --source "demo"

Step "8. Unknown action pauses for clarification"
mg add examples\task_unknown_action.md
mg clarify MG-T-0003 --by glow --actions "read_file: C:/Users/Eric/practice_files"

Step "9. Reviewed memory: worker candidate -> Eric scope -> Glow approves"
mg memory propose project_context "Practice folder holds 12 files" --source "MG-T-0001 evidence" --scope mini-glow
mg proposals
mg proposal approve 8 --by glow
mg scope allow mini-glow --by eric
mg proposal approve 8 --by glow
mg memory show project_context

Step "10. Restart check, health, backup, audit export"
mg recover
mg verify
mg backup --zip
mg export-log
mg log --task MG-T-0001

Write-Host "`nDemo data lives in $env:MINI_GLOW_HOME" -ForegroundColor Green
