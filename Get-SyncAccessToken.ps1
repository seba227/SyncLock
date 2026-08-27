<#
.SYNOPSIS
    End-to-end: mints an Entra ID access token for the Entra Connect Sync service
    principal, using the sync identity certificate that only the gMSA can reach.

.DESCRIPTION
    Self-contained single-file version of the SyncLock flow. In one run it:

      1. Discovers the ADSync gMSA and, via a one-shot scheduled task, runs a
         signing block AS that account (a local admin cannot make CurrentUser
         resolve to the gMSA, but can launch a process as it).
      2. Inside the gMSA context, locates the sync identity certificate, builds a
         client assertion (private_key_jwt) and signs it with the private key -
         PS256 / 'x5t#S256', matching Entra's own sync assertion.
      3. POSTs the assertion to the tenant token endpoint (client_credentials)
         and returns the access token.

    Must be run elevated, on the Entra Connect Sync server (an authorized host
    for the gMSA). Everything except the tenant and client id is fixed below.

.EXAMPLE
    .\Get-SyncAccessToken.ps1 -TenantId 'contoso.onmicrosoft.com' -ClientId '<sync-sp-appid>'
#>

[CmdletBinding()]
param(
    # Tenant GUID or verified domain, e.g. 'contoso.onmicrosoft.com'.
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $TenantId,

    # AppId of the per-tenant Entra Connect Sync service principal. Also the
    # assertion's iss/sub.
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ClientId
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------------------------------------------------------
# Fixed configuration (previously the tunable parameters).
# -------------------------------------------------------------------------
$CertificateSubject       = 'CN=Entra Connect Sync Provisioning'
$AssertionLifetimeMinutes = 10
$Scope                    = '6bf85cfa-ac8a-4be5-b5de-425a0d0dc016/.default'
$TimeoutSeconds           = 60
$ClientAssertionType      = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
$tokenEndpoint            = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId

# =========================================================================
# Run-as-gMSA machinery (inlined from Invoke-AsSyncAccount.ps1)
# =========================================================================

function Assert-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must be run from an elevated (Run as administrator) session.'
    }
}

function Resolve-GmsaAccount {
    param([Parameter(Mandatory = $true)] [string] $Pattern)

    # A gMSA is a domain account, not a local user, so it is not in Get-LocalUser.
    # It does leave two local footprints we can match: the account the ADSync
    # service runs as, and the profile directory it created under C:\Users.
    $candidates = New-Object System.Collections.Generic.List[string]

    $service = Get-CimInstance Win32_Service -Filter "Name='ADSync'" -ErrorAction SilentlyContinue
    if ($service -and $service.StartName) {
        $leaf = ($service.StartName -split '\\')[-1]
        if ($leaf -like $Pattern) { $candidates.Add($service.StartName) }
    }

    Get-ChildItem -Path 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like $Pattern } |
        ForEach-Object { $candidates.Add("$env:USERDOMAIN\$($_.Name)") }

    $unique = @($candidates | Sort-Object -Unique)

    if ($unique.Count -eq 0) {
        throw (@(
            "Could not find a gMSA matching '$Pattern' from the ADSync service account or C:\Users profiles.",
            "Check the ADSync service account with:",
            "  (Get-CimInstance Win32_Service -Filter `"Name='ADSync'`").StartName"
        ) -join [Environment]::NewLine)
    }
    if ($unique.Count -gt 1) {
        throw ("Found multiple accounts matching '$Pattern': {0}." -f ($unique -join ', '))
    }
    return $unique[0]
}

function Invoke-AsGmsa {
    param(
        [Parameter(Mandatory = $true)] [string] $GmsaAccount,
        [Parameter(Mandatory = $true)] [string] $Command
    )

    # Unique task name plus a scratch directory the task writes its output to. It
    # lives under ProgramData (not the admin's TEMP, which the gMSA cannot write
    # to) and is explicitly granted to the gMSA.
    $taskName = "SyncLock_Token_$([Guid]::NewGuid().ToString('N').Substring(0, 8))"
    $workDir = Join-Path $env:ProgramData "SyncLock\$taskName"
    $outputFile = Join-Path $workDir 'out.txt'
    $errorFile = Join-Path $workDir 'err.txt'

    New-Item -ItemType Directory -Path $workDir -Force | Out-Null
    & icacls.exe $workDir /grant "$($GmsaAccount):(OI)(CI)M" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not grant '$GmsaAccount' write access to '$workDir' (icacls exit $LASTEXITCODE)."
    }

    # '*>' redirects every stream including stderr, so stderr is split out with a
    # separate inner redirect.
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
            -Settings $settings -Description 'SyncLock token flow (run as gMSA)' | Out-Null
        $registered = $true

        Start-ScheduledTask -TaskName $taskName

        # Poll LastTaskResult, not State: State is unreliable right after a start.
        $SCHED_S_TASK_RUNNING = 0x41301
        $SCHED_S_TASK_HAS_NOT_RUN = 0x41303

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        do {
            Start-Sleep -Milliseconds 500
            $info = Get-ScheduledTaskInfo -TaskName $taskName
            $pending = $info.LastTaskResult -in @($SCHED_S_TASK_RUNNING, $SCHED_S_TASK_HAS_NOT_RUN)
        } while ($pending -and (Get-Date) -lt $deadline)

        if ($pending) {
            throw "gMSA task '$taskName' did not finish within $TimeoutSeconds seconds (LastResult 0x$('{0:X8}' -f $info.LastTaskResult))."
        }

        # Get-Content -Raw returns $null for an empty file, so coalesce.
        $stdout = if (Test-Path $outputFile) { Get-Content $outputFile -Raw } else { $null }
        $stderr = if (Test-Path $errorFile) { Get-Content $errorFile -Raw } else { $null }
        if ($null -eq $stdout) { $stdout = '' }
        if ($null -eq $stderr) { $stderr = '' }

        return [pscustomobject] @{
            Output = $stdout.TrimEnd()
            Errors = $stderr.TrimEnd()
        }
    }
    finally {
        if ($registered) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        }
        Remove-Item $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =========================================================================
# Token machinery (inlined from New-SyncClientAssertion.ps1)
# =========================================================================

function Get-WebExceptionBody {
    param([Parameter(Mandatory = $true)] $ErrorRecord)
    # PowerShell 7 keeps the response body on the error record; 5.1 needs the raw stream.
    if ($null -ne $ErrorRecord.ErrorDetails -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.ErrorDetails.Message)) {
        return $ErrorRecord.ErrorDetails.Message
    }
    $response = $ErrorRecord.Exception.Response
    if ($null -eq $response -or $null -eq ($response | Get-Member -Name 'GetResponseStream')) {
        return $ErrorRecord.Exception.Message
    }
    $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
    try { return $reader.ReadToEnd() } finally { $reader.Close() }
}

function Request-AccessToken {
    param(
        [Parameter(Mandatory = $true)] [string] $TokenEndpoint,
        [Parameter(Mandatory = $true)] [string] $Assertion
    )

    # Build the body by hand so the wire format is exactly:
    #   client_id=...&client_assertion_type=...&client_assertion=...&scope=...&grant_type=client_credentials
    # EscapeDataString gives the '%2F' / '%3A' encoding the endpoint expects.
    $fields = [ordered] @{
        client_id             = $ClientId
        client_assertion_type = $ClientAssertionType
        client_assertion      = $Assertion
        scope                 = $Scope
        grant_type            = 'client_credentials'
    }
    $body = ($fields.GetEnumerator() | ForEach-Object {
        '{0}={1}' -f $_.Key, [System.Uri]::EscapeDataString([string] $_.Value)
    }) -join '&'

    try {
        return Invoke-RestMethod -Method Post -Uri $TokenEndpoint -Body $body `
            -ContentType 'application/x-www-form-urlencoded' -UseBasicParsing
    }
    catch {
        throw "Token request to $TokenEndpoint failed: $(Get-WebExceptionBody -ErrorRecord $_)"
    }
}

# -------------------------------------------------------------------------
# The signing block, executed inside the gMSA context. Single-quoted here-string
# so nothing expands here; config values are substituted below. It prints a
# one-line JSON object (assertion + exp + cert identity) to stdout.
# -------------------------------------------------------------------------
$signingTemplate = @'
$ErrorActionPreference = 'Stop'
$ClientId    = '__CLIENTID__'
$Audience    = '__AUDIENCE__'
$WantSubject = '__CERTSUBJECT__'
$LifetimeMin = __LIFETIME__

function ConvertTo-Base64Url([byte[]] $Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
function ConvertTo-Base64UrlJson($Object) {
    $json = $Object | ConvertTo-Json -Depth 5 -Compress
    ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($json))
}

# The sync identity certificate is not reliably in \My, so sweep every store
# name in the gMSA's CurrentUser location.
$matched = New-Object System.Collections.Generic.List[object]
foreach ($name in [Enum]::GetNames([System.Security.Cryptography.X509Certificates.StoreName])) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'CurrentUser')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($c in $store.Certificates) {
            if ($c.Subject -like "*$WantSubject*") { $matched.Add($c) }
        }
    } catch { } finally { $store.Close() }
}

$now = [DateTime]::Now
$cert = @($matched |
    Where-Object { $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now } |
    Sort-Object NotAfter -Descending)[0]
if (-not $cert) {
    throw "No usable sync identity certificate (subject like '$WantSubject') with a private key in this account's CurrentUser stores."
}

$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($null -eq $rsa) { throw "Could not open the RSA private key for $($cert.Thumbprint)." }
try {
    # Entra's own assertion identifies the key with the SHA-256 thumbprint
    # ('x5t#S256'), not the legacy SHA-1 'x5t'. Compute it portably rather than
    # relying on the GetCertHash(HashAlgorithmName) overload (absent on 5.1).
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try { $certHashS256 = $sha256.ComputeHash($cert.RawData) } finally { $sha256.Dispose() }

    # [ordered] so the serialized header/payload keep the exact field order of
    # the reference assertion.
    $header = [ordered] @{
        alg        = 'PS256'
        typ        = 'JWT'
        'x5t#S256' = ConvertTo-Base64Url $certHashS256
    }

    $issued = [DateTimeOffset]::UtcNow
    $exp = [long] $issued.AddMinutes($LifetimeMin).ToUnixTimeSeconds()
    # No 'iat' - the reference assertion omits it. Order: aud, iss, sub, nbf, exp, jti.
    $payload = [ordered] @{
        aud = $Audience
        iss = $ClientId
        sub = $ClientId
        nbf = [long] $issued.ToUnixTimeSeconds()
        exp = $exp
        jti = [Guid]::NewGuid().ToString()
    }

    $signingInput = '{0}.{1}' -f (ConvertTo-Base64UrlJson $header), (ConvertTo-Base64UrlJson $payload)
    # PS256 = RSASSA-PSS with SHA-256, so the padding is Pss, not Pkcs1.
    $signature = $rsa.SignData(
        [System.Text.Encoding]::ASCII.GetBytes($signingInput),
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pss)
    $assertion = '{0}.{1}' -f $signingInput, (ConvertTo-Base64Url $signature)

    [pscustomobject] @{
        assertion  = $assertion
        exp        = $exp
        thumbprint = $cert.Thumbprint
        subject    = $cert.Subject
    } | ConvertTo-Json -Compress
}
finally {
    if ($rsa -is [System.IDisposable]) { $rsa.Dispose() }
}
'@

# =========================================================================
# Main
# =========================================================================

Assert-Elevated

$gmsaAccount = Resolve-GmsaAccount -Pattern 'ADSync*$'
Write-Verbose "Discovered gMSA account: $gmsaAccount"

$signingScript = $signingTemplate.
    Replace('__CLIENTID__',    $ClientId.Replace("'", "''")).
    Replace('__AUDIENCE__',    $tokenEndpoint.Replace("'", "''")).
    Replace('__CERTSUBJECT__', $CertificateSubject.Replace("'", "''")).
    Replace('__LIFETIME__',    [string] $AssertionLifetimeMinutes)

Write-Verbose "Signing the client assertion as $gmsaAccount"
$run = Invoke-AsGmsa -GmsaAccount $gmsaAccount -Command $signingScript

if ([string]::IsNullOrWhiteSpace($run.Output)) {
    $detail = if (-not [string]::IsNullOrWhiteSpace($run.Errors)) { $run.Errors } else { 'no output' }
    throw "The gMSA signing task produced no assertion. $detail"
}

try {
    $signed = $run.Output | ConvertFrom-Json
}
catch {
    throw "Could not parse the gMSA output as JSON. Raw output:`n$($run.Output)`nErrors:`n$($run.Errors)"
}

# TLS 1.2/1.3 for the token POST (older .NET Framework defaults are too low).
$securityProtocol = [System.Net.SecurityProtocolType]::Tls12
try {
    $securityProtocol = $securityProtocol -bor [Enum]::Parse([System.Net.SecurityProtocolType], 'Tls13')
}
catch {
    # Older .NET Framework builds do not expose TLS 1.3.
}
[System.Net.ServicePointManager]::SecurityProtocol = $securityProtocol

Write-Verbose "Redeeming the assertion for an access token at $tokenEndpoint"
$response = Request-AccessToken -TokenEndpoint $tokenEndpoint -Assertion $signed.assertion

$tokenExpiresOnUtc = $null
if ($null -ne $response.expires_in) {
    $tokenExpiresOnUtc = [DateTimeOffset]::UtcNow.AddSeconds([int] $response.expires_in).UtcDateTime
}

[pscustomobject] @{
    AccessToken       = $response.access_token
    TokenType         = $response.token_type
    TokenExpiresOnUtc = $tokenExpiresOnUtc
    Scope             = $Scope
    ClientId          = $ClientId
    TokenEndpoint     = $tokenEndpoint
    Thumbprint        = $signed.thumbprint
    Subject           = $signed.subject
    RanAs             = $gmsaAccount
}
