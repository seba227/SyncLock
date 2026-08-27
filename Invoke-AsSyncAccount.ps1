<#
.SYNOPSIS
    Runs a command in the context of the ADSync group-managed service account
    (gMSA) by registering, starting, and removing a one-shot scheduled task.

.DESCRIPTION
    A local admin cannot make 'CurrentUser' resolve to the gMSA's profile, but
    can launch a process AS the gMSA. A gMSA has no typed password; the host
    retrieves it from AD, so the scheduled-task principal uses -LogonType
    Password with no credential supplied.

    For now the task just runs whoami so you can confirm the identity swap works
    before wiring up the certificate / token flow.

    Must be run elevated. The machine must be an authorized host for the gMSA.

.EXAMPLE
    .\Invoke-AsSyncAccount.ps1 -GmsaAccount 'BANANA\ADSyncMSAa2f13$'
#>

[CmdletBinding()]
param(
    # The gMSA the ADSync service runs as. Find it with:
    #   (Get-CimInstance Win32_Service -Filter "Name='ADSync'").StartName
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $GmsaAccount,

    # Command line executed as the gMSA. Defaults to whoami.
    [string] $Command = 'whoami /all',

    # How long to wait for the one-shot task to finish.
    [ValidateRange(5, 600)]
    [int] $TimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run from an elevated (Run as administrator) session.'
    }
}

Assert-Elevated

# Unique task name plus a scratch directory the task writes its output to. It
# lives under ProgramData (not the admin's TEMP, which the gMSA cannot write to)
# and is explicitly granted to the gMSA so the redirected streams land somewhere
# both identities can reach.
$taskName = "SyncLock_RunAs_$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
$workDir = Join-Path $env:ProgramData "SyncLock\$taskName"
$outputFile = Join-Path $workDir 'out.txt'
$errorFile = Join-Path $workDir 'err.txt'

New-Item -ItemType Directory -Path $workDir -Force | Out-Null
# Grant the gMSA Modify on the scratch dir (object + container inherit).
& icacls.exe $workDir /grant "$($GmsaAccount):(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not grant '$GmsaAccount' write access to '$workDir' (icacls exit $LASTEXITCODE)."
}

# Wrap the target command so stdout and stderr are captured to files the admin
# can read back. '*>' already redirects every stream including stderr, so stderr
# is split out with a separate inner redirect.
$innerCommand = "try { & { $Command } 1> '$outputFile' 2> '$errorFile' } catch { `$_ | Out-File -FilePath '$errorFile' -Append; exit 1 }"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($innerCommand))

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand $encoded"

# gMSA principal: -LogonType Password, no password. The host fetches it from AD.
$principal = New-ScheduledTaskPrincipal -UserId $GmsaAccount -LogonType Password -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds)

$registered = $false
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal `
        -Settings $settings -Description 'SyncLock one-shot run-as-gMSA probe' | Out-Null
    $registered = $true

    Start-ScheduledTask -TaskName $taskName

    # Poll LastTaskResult, not State: Task Scheduler reports State unreliably
    # right after a start, but these result codes are authoritative.
    $SCHED_S_TASK_RUNNING = 0x41301  # task is currently running
    $SCHED_S_TASK_HAS_NOT_RUN = 0x41303  # queued, not yet launched

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Milliseconds 500
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        $pending = $info.LastTaskResult -in @($SCHED_S_TASK_RUNNING, $SCHED_S_TASK_HAS_NOT_RUN)
    } while ($pending -and (Get-Date) -lt $deadline)

    if ($pending) {
        throw "Task '$taskName' did not finish within $TimeoutSeconds seconds (LastResult still 0x$('{0:X8}' -f $info.LastTaskResult))."
    }

    # Get-Content -Raw returns $null for an empty file, so coalesce before trimming.
    $stdout = if (Test-Path $outputFile) { Get-Content $outputFile -Raw } else { $null }
    $stderr = if (Test-Path $errorFile) { Get-Content $errorFile -Raw } else { $null }
    if ($null -eq $stdout) { $stdout = '' }
    if ($null -eq $stderr) { $stderr = '' }

    [pscustomobject] @{
        RanAs        = $GmsaAccount
        Command      = $Command
        LastResult   = ('0x{0:X8}' -f $info.LastTaskResult)
        OutputFile   = $outputFile
        WroteOutput  = (Test-Path $outputFile)
        Output       = $stdout.TrimEnd()
        Errors       = $stderr.TrimEnd()
    }
}
finally {
    if ($registered) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
