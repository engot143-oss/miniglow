$ErrorActionPreference = 'Stop'
$mgBase = Split-Path -Parent $PSScriptRoot
$mgPython = (Get-Command python -ErrorAction Stop).Source
$mgWorker = Join-Path $PSScriptRoot 'worker.py'
$mgControl = Join-Path $mgBase 'workspace\control'
$mgStatusText = & $mgPython $mgWorker status
if ($LASTEXITCODE -ne 0) { throw 'Worker configuration needs attention. See AUTOMATION.md.' }
$mgStatus = ($mgStatusText -join "`n") | ConvertFrom-Json
# Do not restart after an explicit Stop during Windows login.
if ($args -contains '-AtLogin' -and $mgStatus.stop_requested) { exit 0 }
if (Test-Path -LiteralPath (Join-Path $mgBase 'ai\ENABLED')) {
    & $mgPython (Join-Path $PSScriptRoot 'start_model.py')
    if ($LASTEXITCODE -ne 0) { throw 'Local model is unavailable. Automatic AI tasks remain blocked.' }
}
if ($mgStatus.running) { Write-Output 'MiniGlow is already running offline.'; exit 0 }
$mgStdout = Join-Path $mgControl 'worker.stdout.log'
$mgStderr = Join-Path $mgControl 'worker.stderr.log'
$mgProcess = Start-Process -FilePath $mgPython -ArgumentList @(('"' + $mgWorker + '"'), 'run') -WorkingDirectory $mgBase -WindowStyle Hidden -RedirectStandardOutput $mgStdout -RedirectStandardError $mgStderr -PassThru
Start-Sleep -Seconds 2
$mgProcess.Refresh()
if ($mgProcess.HasExited) { throw 'MiniGlow did not stay running. Check the worker error log.' }
Write-Output ('MiniGlow started offline. Process ' + $mgProcess.Id)
