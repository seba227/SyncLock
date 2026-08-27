<#
.SYNOPSIS
    Signs an OAuth 2.0 client assertion (private_key_jwt) with the Entra Connect
    sync identity certificate that only the gMSA can reach, then redeems it for
    an access token.

.DESCRIPTION
    Signing the assertion needs the sync identity certificate's private key,
    which lives in the gMSA's CurrentUser store and is not readable by the admin.
    Fetching the token, by contrast, needs no special identity - it is just a
    form POST of the assertion to the tenant token endpoint.

    This script does both halves:

      1. Build a self-contained signing block and run it AS the gMSA through
         Invoke-AsSyncAccount.ps1. Inside that context it locates the sync
         identity certificate, builds a JWT and signs it with the private key
         (PS256, matching Entra's own sync assertion), and prints it back out.
      2. POST the assertion to the tenant token endpoint (client_credentials)
         and return the access token. Use -AssertionOnly to stop after step 1.

    The assertion embeds 'exp', so redeem it promptly - Entra rejects assertions
    older than ~10 minutes.

    Must be run elevated (Invoke-AsSyncAccount.ps1 requires it).

.EXAMPLE
    # Full flow: sign as the gMSA, then fetch the token.
    $r = .\New-SyncClientAssertion.ps1 -TenantId 'contoso.onmicrosoft.com' `
            -ClientId '<sync-sp-appid>' -ShowClaims
    $r.AccessToken

.EXAMPLE
    # Just the signed assertion, to redeem elsewhere later.
    $a = .\New-SyncClientAssertion.ps1 -TenantId 'contoso.onmicrosoft.com' `
            -ClientId '<sync-sp-appid>' -AssertionOnly
#>

[CmdletBinding()]
param(
    # Tenant GUID or verified domain, e.g. 'contoso.onmicrosoft.com'.
    [string] $TenantId = '<TENANT_ID_PLACEHOLDER>',

    # AppId of the per-tenant Entra Connect Sync service principal.
    [string] $ClientId = '<SYNC_SP_CLIENT_ID_PLACEHOLDER>',

    # Which token endpoint the assertion is bound to (its 'aud'). The later token
    # request MUST go to this same endpoint, or Entra rejects the assertion.
    [ValidateSet('v2.0', 'v1.0')]
    [string] $TokenVersion = 'v2.0',

    # Subject of the sync identity certificate as provisioned by Entra Connect.
    [string] $CertificateSubject = 'CN=Entra Connect Sync Provisioning',

    # Optional exact thumbprint. Takes precedence over -CertificateSubject.
    [string] $CertificateThumbprint,

    # Entra rejects assertions valid much longer than this.
    [ValidateRange(1, 10)]
    [int] $AssertionLifetimeMinutes = 10,

    # Embed the full certificate ('x5c') instead of only the 'x5t' hint. Needed
    # when the app registration requires the leaf chain in the header.
    [switch] $IncludeX5c,

    # The '.default' scope posted with the token request. Defaults to the sync
    # service's own resource.
    [string] $Scope = '6bf85cfa-ac8a-4be5-b5de-425a0d0dc016/.default',

    # Stop after signing and just return the assertion; skip the token request.
    [switch] $AssertionOnly,

    # Also emit the decoded header and claims of the returned access token.
    [switch] $ShowClaims,

    # Passed straight through to Invoke-AsSyncAccount.ps1 when set; otherwise the
    # gMSA is auto-discovered there.
    [string] $GmsaAccount,

    # The run-as helper. Defaults to the copy next to this script.
    [string] $InvokeScript = (Join-Path $PSScriptRoot 'Invoke-AsSyncAccount.ps1'),

    # How long to wait for the gMSA signing task to finish.
    [ValidateRange(5, 600)]
    [int] $TimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-NotPlaceholder {
    param(
        [Parameter(Mandatory = $true)] [string] $Name,
        [AllowEmptyString()] [AllowNull()] [string] $Value
    )
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -like '<*PLACEHOLDER>') {
        throw "Parameter -$Name is still a placeholder. Supply a real value (currently '$Value')."
    }
}

$ClientAssertionType = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'

function ConvertFrom-Base64Url {
    param([Parameter(Mandatory = $true)] [string] $Text)
    $padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($padded.Length % 4) {
        2 { $padded += '==' }
        3 { $padded += '=' }
        1 { throw 'Invalid base64url input.' }
    }
    return [Convert]::FromBase64String($padded)
}

function ConvertFrom-Jwt {
    param([Parameter(Mandatory = $true)] [string] $Jwt)
    $parts = $Jwt.Split('.')
    if ($parts.Count -lt 2) { throw 'The returned token is not a JWT, so it cannot be decoded.' }
    return [pscustomobject] @{
        Header  = [System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[0])) | ConvertFrom-Json
        Payload = [System.Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $parts[1])) | ConvertFrom-Json
    }
}

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

Assert-NotPlaceholder -Name 'TenantId' -Value $TenantId
Assert-NotPlaceholder -Name 'ClientId' -Value $ClientId

if (-not (Test-Path -LiteralPath $InvokeScript)) {
    throw "Run-as helper not found at '$InvokeScript'. Point -InvokeScript at Invoke-AsSyncAccount.ps1."
}

# The assertion audience is the exact endpoint it will be posted to.
if ($TokenVersion -eq 'v2.0') {
    $tokenEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/v2.0/token' -f $TenantId
}
else {
    $tokenEndpoint = 'https://login.microsoftonline.com/{0}/oauth2/token' -f $TenantId
}

# -------------------------------------------------------------------------
# Signing block, executed inside the gMSA context. Single-quoted here-string
# so nothing expands here; config values are substituted below. It prints a
# one-line JSON object (assertion + exp + cert identity) to stdout, which is all
# Invoke-AsSyncAccount.ps1 hands back.
# -------------------------------------------------------------------------
$signingTemplate = @'
$ErrorActionPreference = 'Stop'
$ClientId    = '__CLIENTID__'
$Audience    = '__AUDIENCE__'
$WantSubject = '__CERTSUBJECT__'
$WantThumb   = '__CERTTHUMB__'
$LifetimeMin = __LIFETIME__
$IncludeX5c  = __INCLUDEX5C__

function ConvertTo-Base64Url([byte[]] $Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
function ConvertTo-Base64UrlJson($Object) {
    $json = $Object | ConvertTo-Json -Depth 5 -Compress
    ConvertTo-Base64Url ([System.Text.Encoding]::UTF8.GetBytes($json))
}

$thumb = if ($WantThumb) { $WantThumb -replace '[^0-9a-fA-F]', '' } else { $null }

# The sync identity certificate is not reliably in \My, so sweep every store
# name in the gMSA's CurrentUser location.
$matched = New-Object System.Collections.Generic.List[object]
foreach ($name in [Enum]::GetNames([System.Security.Cryptography.X509Certificates.StoreName])) {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($name, 'CurrentUser')
    try {
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
        foreach ($c in $store.Certificates) {
            $isMatch = if ($thumb) { $c.Thumbprint -eq $thumb } else { $c.Subject -like "*$WantSubject*" }
            if ($isMatch) { $matched.Add($c) }
        }
    } catch { } finally { $store.Close() }
}

$now = [DateTime]::Now
$cert = @($matched |
    Where-Object { $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now } |
    Sort-Object NotAfter -Descending)[0]
if (-not $cert) {
    $crit = if ($thumb) { "thumbprint '$thumb'" } else { "subject like '$WantSubject'" }
    throw "No usable sync identity certificate ($crit) with a private key in this account's CurrentUser stores."
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
    if ($IncludeX5c) { $header['x5c'] = @([Convert]::ToBase64String($cert.RawData)) }

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

$x5cLiteral = if ($IncludeX5c) { '$true' } else { '$false' }

$signingScript = $signingTemplate.
    Replace('__CLIENTID__',   $ClientId.Replace("'", "''")).
    Replace('__AUDIENCE__',   $tokenEndpoint.Replace("'", "''")).
    Replace('__CERTSUBJECT__', $CertificateSubject.Replace("'", "''")).
    Replace('__CERTTHUMB__',  ([string] $CertificateThumbprint).Replace("'", "''")).
    Replace('__LIFETIME__',   [string] $AssertionLifetimeMinutes).
    Replace('__INCLUDEX5C__', $x5cLiteral)

# -------------------------------------------------------------------------
# Run the signing block as the gMSA and collect the JSON it prints.
# -------------------------------------------------------------------------
$invokeArgs = @{
    Command        = $signingScript
    TimeoutSeconds = $TimeoutSeconds
}
if (-not [string]::IsNullOrWhiteSpace($GmsaAccount)) { $invokeArgs['GmsaAccount'] = $GmsaAccount }

Write-Verbose "Requesting a signed assertion from the gMSA via $InvokeScript"
$run = & $InvokeScript @invokeArgs

if (-not $run.WroteOutput -or [string]::IsNullOrWhiteSpace($run.Output)) {
    $detail = if (-not [string]::IsNullOrWhiteSpace($run.Errors)) { $run.Errors } else { "LastResult $($run.LastResult)" }
    throw "The gMSA signing task produced no assertion. $detail"
}

try {
    $signed = $run.Output | ConvertFrom-Json
}
catch {
    throw "Could not parse the gMSA output as JSON. Raw output:`n$($run.Output)`nErrors:`n$($run.Errors)"
}

$assertionExpiresOnUtc = [DateTimeOffset]::FromUnixTimeSeconds([long] $signed.exp).UtcDateTime

$result = [pscustomobject] @{
    ClientAssertion       = $signed.assertion
    TokenEndpoint         = $tokenEndpoint
    ClientId              = $ClientId
    TokenVersion          = $TokenVersion
    Scope                 = $Scope
    Thumbprint            = $signed.thumbprint
    Subject               = $signed.subject
    RanAs                 = $run.RanAs
    AssertionExpiresOnUtc = $assertionExpiresOnUtc
}

if ($AssertionOnly) {
    return $result
}

# -------------------------------------------------------------------------
# Exchange the assertion for an access token.
# -------------------------------------------------------------------------
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

$result | Add-Member -NotePropertyName 'AccessToken' -NotePropertyValue $response.access_token
$result | Add-Member -NotePropertyName 'TokenType' -NotePropertyValue $response.token_type
$result | Add-Member -NotePropertyName 'TokenExpiresOnUtc' -NotePropertyValue $tokenExpiresOnUtc

if ($ShowClaims) {
    $decoded = ConvertFrom-Jwt -Jwt $response.access_token
    $result | Add-Member -NotePropertyName 'Header' -NotePropertyValue $decoded.Header
    $result | Add-Member -NotePropertyName 'Claims' -NotePropertyValue $decoded.Payload
}

$result
