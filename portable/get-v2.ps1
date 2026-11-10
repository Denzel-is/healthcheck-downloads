[CmdletBinding()]
param(
    [string]$Code,
    [string]$PackagePath,
    [string]$Destination,
    [switch]$Bluetooth,
    [switch]$PortableBluetooth,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$maximumPackageBytes = 4MB
if ($Bluetooth -and $PortableBluetooth) { throw 'Choose one Bluetooth build.' }
$packageUrl = if ($PortableBluetooth) {
    'https://raw.githubusercontent.com/Denzel-is/healthcheck-downloads/main/portable/healthcheck-bluetooth-overlay-20261110.hcp'
} elseif ($Bluetooth) {
    'https://raw.githubusercontent.com/Denzel-is/healthcheck-downloads/main/bluetooth/healthcheck-bluetooth-20261110.hcp'
} else { 'https://raw.githubusercontent.com/Denzel-is/healthcheck-downloads/main/native/healthcheck-20261110.hcp' }

function Get-FullFilePath([string]$Path) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Assert-Destination([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $existing = Get-Item -LiteralPath $Path -Force
    if ($existing.PSIsContainer -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'The destination must be a regular executable file.'
    }
    if (-not $Force) { throw "Destination already exists: $Path. Use -Force to replace it." }
}

function Read-LimitedPackage([IO.Stream]$Stream) {
    $buffer = New-Object byte[] 16384
    $content = New-Object IO.MemoryStream
    try {
        while (($count = $Stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($content.Length + $count -gt $maximumPackageBytes) { throw 'Package exceeds the 4 MB limit.' }
            $content.Write($buffer, 0, $count)
        }
        return ,$content.ToArray()
    } finally { $content.Dispose() }
}

function Read-RemotePackage {
    $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
    $response = $null
    try {
        if ($PSVersionTable.PSVersion.Major -le 5) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        $request = [Net.WebRequest]::Create($packageUrl)
        $request.AllowAutoRedirect = $false
        $request.Timeout = 30000
        $request.ReadWriteTimeout = 30000
        $response = $request.GetResponse()
        if ($response.ContentLength -gt $maximumPackageBytes) { throw 'Package exceeds the 4 MB limit.' }
        $stream = $response.GetResponseStream()
        try { return ,(Read-LimitedPackage $stream) } finally { $stream.Dispose() }
    } finally {
        if ($response) { $response.Dispose() }
        if ($PSVersionTable.PSVersion.Major -le 5) { [Net.ServicePointManager]::SecurityProtocol = $previousProtocol }
    }
}

function New-PackageKey([byte[]]$Master, [string]$Context) {
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $Master
        return ,$hmac.ComputeHash([Text.Encoding]::ASCII.GetBytes($Context))
    } finally { $hmac.Dispose() }
}

if (-not $Destination) {
    $binaryName = if ($PortableBluetooth) { 'HealthCheck-Bluetooth-Portable.exe' }
        elseif ($Bluetooth) { 'HealthCheck-Bluetooth-C.exe' }
        else { 'HealthCheck.exe' }
    $Destination = Join-Path ([Environment]::GetFolderPath('Desktop')) $binaryName
}
$destinationPath = Get-FullFilePath $Destination
$destinationDirectory = [IO.Path]::GetDirectoryName($destinationPath)
if ([IO.Path]::GetExtension($destinationPath) -ne '.exe' -or -not [IO.Directory]::Exists($destinationDirectory)) {
    throw 'Choose an .exe destination in an existing folder.'
}
Assert-Destination $destinationPath

if ($PackagePath) {
    $inputPath = Get-FullFilePath $PackagePath
    if ($inputPath -eq $destinationPath) { throw 'Choose distinct package and executable paths.' }
    $stream = [IO.File]::Open($inputPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { $package = Read-LimitedPackage $stream } finally { $stream.Dispose() }
} else { $package = Read-RemotePackage }

if ($package.Length -lt 72 -or ($package.Length - 56) % 16 -ne 0 -or
    [Text.Encoding]::ASCII.GetString($package, 0, 8) -cne 'HCKPKG01') {
    throw 'Package format is invalid.'
}

$master = $encKey = $macKey = $plain = $null
$tempPath = $null
try {
    if (-not $PSBoundParameters.ContainsKey('Code')) {
        $secureCode = Read-Host 'HealthCheck private unlock code' -AsSecureString
        try {
            $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureCode)
            try { $Code = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
            finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
        } finally { $secureCode.Dispose() }
    }
    $Code = $Code.Trim()
    if ($Code -cnotmatch '\A[A-Za-z0-9_-]{43}\z') { throw 'Invalid private unlock code format.' }
    $master = [Convert]::FromBase64String($Code.Replace('-', '+').Replace('_', '/') + '=')
    $Code = $null
    $encKey = New-PackageKey $master 'HealthCheck download v1 encryption'
    $macKey = New-PackageKey $master 'HealthCheck download v1 authentication'

    $tagOffset = $package.Length - 32
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    try {
        $hmac.Key = $macKey
        $expectedTag = $hmac.ComputeHash($package, 0, $tagOffset)
    } finally { $hmac.Dispose() }
    $difference = 0
    for ($i = 0; $i -lt 32; $i++) {
        $difference = $difference -bor ($expectedTag[$i] -bxor $package[$tagOffset + $i])
    }
    if ($difference -ne 0) { throw 'Package verification failed. Check the private code and package.' }

    $iv = New-Object byte[] 16
    [Buffer]::BlockCopy($package, 8, $iv, 0, 16)
    $aes = [Security.Cryptography.Aes]::Create()
    try {
        $aes.KeySize = 256
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
        $decryptor = $aes.CreateDecryptor($encKey, $iv)
        try { $plain = $decryptor.TransformFinalBlock($package, 24, $tagOffset - 24) }
        finally { $decryptor.Dispose() }
    } finally { $aes.Dispose() }
    if ($plain.Length -lt 68 -or $plain[0] -ne 77 -or $plain[1] -ne 90) { throw 'Package has no Windows executable.' }
    $pe = [BitConverter]::ToUInt32($plain, 60)
    if ($pe -lt 64 -or $pe -gt ($plain.Length - 4) -or [BitConverter]::ToUInt32($plain, [int]$pe) -ne 17744) {
        throw 'Package has no Windows executable.'
    }

    $candidateTemp = Join-Path $destinationDirectory ('.HealthCheck-' + [Guid]::NewGuid().ToString('N') + '.tmp')
    $output = [IO.File]::Open($candidateTemp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $tempPath = $candidateTemp
    try { $output.Write($plain, 0, $plain.Length); $output.Flush($true) } finally { $output.Dispose() }

    Assert-Destination $destinationPath
    if ([IO.File]::Exists($destinationPath)) {
        [IO.File]::Replace($tempPath, $destinationPath, [NullString]::Value)
    } else { [IO.File]::Move($tempPath, $destinationPath) }
    $tempPath = $null
} finally {
    $Code = $null
    foreach ($bytes in @($master, $encKey, $macKey, $plain)) {
        if ($bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    if ($tempPath) { [IO.File]::Delete($tempPath) }
}
Write-Output "HealthCheck saved to $destinationPath"
