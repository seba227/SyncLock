param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $CloudAnchor,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $BearerToken
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Cloud anchors for users are always 'User_' followed by a UUID4.
$CloudAnchorPattern = '^User_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$'
if ($CloudAnchor -cnotmatch $CloudAnchorPattern) {
    throw "CloudAnchor '$CloudAnchor' is not valid. Expected the form 'User_<UUID4>', for example 'User_1e0c1b1a-2f3d-4a5b-8c6d-7e8f9a0b1c2d'."
}

$EndpointUrl = 'https://adminwebservice.microsoftonline.com/provisioningservice.svc'
$Action = 'http://schemas.microsoft.com/online/aws/change/2010/01/IProvisioningWebService/Provision'

$ApplicationId = '1651564e-7ce4-4d99-88be-0a65050d8dc3' # Can also use 6eb59a73-39b2-4c23-a70f-e2e3ce8965b1
$TenantId = '00000000-0000-0000-0000-000000000000'

$ClientVersion = '8.0'
$ProtocolVersion = '2.0'
$LanguageId = 'en-US'
$IsInstalledOnDC = 'True'
$IssueDateTime = '0001-01-01T00:00:00'

$ChangedProperties = @(
    'AccountEnabled'
)

$TrackingId = [Guid]::NewGuid().ToString()
$ProvisioningScenario = 'export-Delta-AdHoc'
$ProvisioningSessionDescription = 'manual-old-provision'

function Initialize-WcfBinarySupport {
    if ($PSVersionTable.PSEdition -ne 'Desktop') {
        throw 'This script uses full .NET Framework WCF. Run it with Windows PowerShell 5.1, not PowerShell 7+.'
    }

    try {
        Add-Type -AssemblyName System.ServiceModel
    }
    catch {
        throw "Could not load System.ServiceModel. Run from a FullLanguage Windows PowerShell session. $($_.Exception.Message)"
    }
}

function New-WcfBinaryEncoder {
    $encoding = New-Object System.ServiceModel.Channels.BinaryMessageEncodingBindingElement
    $encoding.ReaderQuotas.MaxArrayLength = [int]::MaxValue
    $encoding.ReaderQuotas.MaxStringContentLength = [int]::MaxValue

    return $encoding.CreateMessageEncoderFactory().Encoder
}

function Write-ElementString {
    param(
        [Parameter(Mandatory = $true)]
        [System.Xml.XmlWriter] $Writer,

        [Parameter(Mandatory = $true)]
        [string] $LocalName,

        [Parameter(Mandatory = $true)]
        [string] $Namespace,

        [AllowNull()]
        [string] $Value
    )

    $Writer.WriteStartElement('', $LocalName, $Namespace)
    if ($null -ne $Value) {
        $Writer.WriteString($Value)
    }
    $Writer.WriteEndElement()
}

function New-OldProvisionSoapXml {
    param(
        [Parameter(Mandatory = $true)]
        [string] $RequestTrackingId
    )

    $nsSoap = 'http://www.w3.org/2003/05/soap-envelope'
    $nsAddressing = 'http://www.w3.org/2005/08/addressing'
    $nsAdmin = 'urn:microsoft.online.administrativeservice'
    $nsChange = 'http://schemas.microsoft.com/online/aws/change/2010/01'
    $nsXsi = 'http://www.w3.org/2001/XMLSchema-instance'
    $nsArrays = 'http://schemas.microsoft.com/2003/10/Serialization/Arrays'

    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.OmitXmlDeclaration = $true
    $settings.Encoding = [System.Text.Encoding]::UTF8
    $settings.Indent = $false

    $builder = New-Object System.Text.StringBuilder
    $writer = [System.Xml.XmlWriter]::Create($builder, $settings)

    try {
        $writer.WriteStartElement('s', 'Envelope', $nsSoap)
        $writer.WriteAttributeString('xmlns', 'a', $null, $nsAddressing)

        $writer.WriteStartElement('s', 'Header', $nsSoap)

        $writer.WriteStartElement('a', 'Action', $nsAddressing)
        $writer.WriteAttributeString('s', 'mustUnderstand', $nsSoap, '1')
        $writer.WriteString($Action)
        $writer.WriteEndElement()

        $writer.WriteStartElement('', 'SyncToken', $nsAdmin)
        $writer.WriteAttributeString('s', 'role', $nsSoap, $nsAdmin)
        $writer.WriteAttributeString('xmlns', 'i', $null, $nsXsi)

        Write-ElementString -Writer $writer -LocalName 'ApplicationId' -Namespace $nsChange -Value $ApplicationId
        Write-ElementString -Writer $writer -LocalName 'BearerToken' -Namespace $nsChange -Value $BearerToken
        Write-ElementString -Writer $writer -LocalName 'ClientVersion' -Namespace $nsChange -Value $ClientVersion
        Write-ElementString -Writer $writer -LocalName 'IsInstalledOnDC' -Namespace $nsChange -Value $IsInstalledOnDC
        Write-ElementString -Writer $writer -LocalName 'IssueDateTime' -Namespace $nsChange -Value $IssueDateTime
        Write-ElementString -Writer $writer -LocalName 'LanguageId' -Namespace $nsChange -Value $LanguageId
        Write-ElementString -Writer $writer -LocalName 'LiveToken' -Namespace $nsChange -Value ''
        Write-ElementString -Writer $writer -LocalName 'ProtocolVersion' -Namespace $nsChange -Value $ProtocolVersion
        Write-ElementString -Writer $writer -LocalName 'TrackingId' -Namespace $nsChange -Value $RequestTrackingId

        $writer.WriteEndElement()
        $writer.WriteEndElement()

        $writer.WriteStartElement('s', 'Body', $nsSoap)
        $writer.WriteStartElement('', 'Provision', $nsChange)

        $writer.WriteStartElement('', 'syncObjects', $nsChange)
        $writer.WriteAttributeString('xmlns', 'a', $null, $nsChange)
        $writer.WriteAttributeString('xmlns', 'i', $null, $nsXsi)

        $writer.WriteStartElement('a', 'SyncObject', $nsChange)
        $writer.WriteAttributeString('i', 'type', $nsXsi, 'a:SyncObjectUser')

        $writer.WriteStartElement('a', 'ChangedProperties', $nsChange)
        $writer.WriteAttributeString('xmlns', 'b', $null, $nsArrays)
        foreach ($propertyName in $ChangedProperties) {
            $writer.WriteElementString('b', 'string', $nsArrays, $propertyName)
        }
        $writer.WriteEndElement()

        $writer.WriteElementString('a', 'CloudAnchor', $nsChange, $CloudAnchor)

        $writer.WriteEndElement()
        $writer.WriteEndElement()

        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndElement()
    }
    finally {
        $writer.Close()
    }

    return $builder.ToString()
}

function ConvertTo-WcfBinarySoap {
    param(
        [Parameter(Mandatory = $true)]
        [string] $SoapXml
    )

    $encoder = New-WcfBinaryEncoder
    $stringReader = New-Object System.IO.StringReader($SoapXml)
    $xmlReader = [System.Xml.XmlReader]::Create($stringReader)
    $message = $null
    $stream = New-Object System.IO.MemoryStream

    try {
        $message = [System.ServiceModel.Channels.Message]::CreateMessage(
            $xmlReader,
            [int]::MaxValue,
            [System.ServiceModel.Channels.MessageVersion]::Soap12WSAddressing10
        )

        $encoder.WriteMessage($message, $stream)
        return $stream.ToArray()
    }
    finally {
        if ($null -ne $message) {
            $message.Close()
        }
        $xmlReader.Close()
        $stringReader.Close()
        $stream.Close()
    }
}

function ConvertFrom-WcfBinarySoap {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes,

        [Parameter(Mandatory = $false)]
        [string] $ContentType = 'application/soap+msbin1'
    )

    $encoder = New-WcfBinaryEncoder
    $stream = New-Object System.IO.MemoryStream(, $Bytes)
    $message = $null
    $writer = $null

    try {
        $message = $encoder.ReadMessage($stream, [int]::MaxValue, $ContentType)

        $settings = New-Object System.Xml.XmlWriterSettings
        $settings.OmitXmlDeclaration = $true
        $settings.Indent = $true

        $builder = New-Object System.Text.StringBuilder
        $writer = [System.Xml.XmlWriter]::Create($builder, $settings)
        $message.WriteMessage($writer)
        $writer.Close()
        $writer = $null

        return $builder.ToString()
    }
    finally {
        if ($null -ne $writer) {
            $writer.Close()
        }
        if ($null -ne $message) {
            $message.Close()
        }
        $stream.Close()
    }
}

function Read-AllBytes {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream] $Stream
    )

    $memory = New-Object System.IO.MemoryStream
    try {
        $Stream.CopyTo($memory)
        return $memory.ToArray()
    }
    finally {
        $memory.Close()
    }
}

function Convert-ResponseBytesToText {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes,

        [Parameter(Mandatory = $false)]
        [string] $ContentType = ''
    )

    if ($ContentType -like '*application/soap+msbin1*') {
        return ConvertFrom-WcfBinarySoap -Bytes $Bytes -ContentType $ContentType
    }

    return [System.Text.Encoding]::UTF8.GetString($Bytes)
}

function Invoke-OldProvisionRequest {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]] $Payload
    )

    $request = [System.Net.HttpWebRequest]::Create($EndpointUrl)
    $request.Method = 'POST'
    $request.ContentType = 'application/soap+msbin1'
    $request.Accept = 'application/soap+msbin1'
    $request.Timeout = 600000
    $request.ReadWriteTimeout = 600000
    $request.ContentLength = $Payload.Length

    # These headers don't really matter, Sync API doesn't parse them
    $request.Headers['x-ms-aadmsods-apiaction'] = 'Provision'
    $request.Headers['x-ms-aadmsods-appid'] = $ApplicationId
    $request.Headers['client-request-id'] = $TrackingId
    $request.Headers['x-ms-aadmsods-clientversion'] = $ClientVersion
    $request.Headers['x-ms-aadmsods-tenantid'] = $TenantId
    $request.Headers['x-ms-aadmsods-machineid'] = 'not-available'
    $request.Headers['x-ms-aadmsods-scenario'] = $ProvisioningScenario
    $request.Headers['x-ms-aadmsods-provisioningsessiondesc'] = $ProvisioningSessionDescription

    $requestStream = $request.GetRequestStream()
    try {
        $requestStream.Write($Payload, 0, $Payload.Length)
    }
    finally {
        $requestStream.Close()
    }

    try {
        $response = [System.Net.HttpWebResponse] $request.GetResponse()
        try {
            $bytes = Read-AllBytes -Stream $response.GetResponseStream()
            $body = Convert-ResponseBytesToText -Bytes $bytes -ContentType $response.ContentType

            [pscustomobject] @{
                StatusCode = [int] $response.StatusCode
                StatusDescription = $response.StatusDescription
                ContentType = $response.ContentType
                Body = $body
            }
        }
        finally {
            $response.Close()
        }
    }
    catch [System.Net.WebException] {
        $webResponse = [System.Net.HttpWebResponse] $_.Exception.Response
        if ($null -eq $webResponse) {
            throw
        }

        try {
            $bytes = Read-AllBytes -Stream $webResponse.GetResponseStream()
            $body = Convert-ResponseBytesToText -Bytes $bytes -ContentType $webResponse.ContentType

            [pscustomobject] @{
                StatusCode = [int] $webResponse.StatusCode
                StatusDescription = $webResponse.StatusDescription
                ContentType = $webResponse.ContentType
                Body = $body
            }
        }
        finally {
            $webResponse.Close()
        }
    }
}

Initialize-WcfBinarySupport

$securityProtocol = [System.Net.SecurityProtocolType]::Tls12
try {
    $securityProtocol = $securityProtocol -bor [Enum]::Parse([System.Net.SecurityProtocolType], 'Tls13')
}
catch {
    # Older .NET Framework builds do not expose TLS 1.3.
}
[System.Net.ServicePointManager]::SecurityProtocol = $securityProtocol

$soapXml = New-OldProvisionSoapXml -RequestTrackingId $TrackingId
$payload = ConvertTo-WcfBinarySoap -SoapXml $soapXml

$result = Invoke-OldProvisionRequest -Payload $payload

if ($result.Body -like '*<ResultCode>Success*') {
    Write-Host ("{0} has been disabled." -f $CloudAnchor)
}
else {
    Write-Host 'User not disabled successfully. An error happened. Here is the response body:'
    Write-Host $result.Body
}
