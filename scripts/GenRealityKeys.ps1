# gen-reality-keys.ps1 - Generate Reality (X25519) key pair + short-id
# Usage: powershell -ExecutionPolicy Bypass -File gen-reality-keys.ps1
# Requires: openssl in PATH

$ErrorActionPreference = "Stop"

# Generate X25519 key pair
$tempFile = Join-Path $env:TEMP "x25519_$(Get-Random).pem"
$null = & openssl genpkey -algorithm X25519 -out $tempFile 2>&1

# Extract private key hex (lines between priv: and pub:)
$privText = & openssl pkey -in $tempFile -text -noout 2>&1 | Where-Object { $_ -is [string] }
$privHex = ""
$capture = $false
foreach ($line in $privText) {
    if ($line -match "priv:") { $capture = $true; continue }
    if ($line -match "pub:") { $capture = $false; continue }
    if ($capture) {
        $privHex += ($line -replace '[\s:]', '')
    }
}

# Extract public key hex (lines between pub: and ASN1)
$pubText = & openssl pkey -in $tempFile -pubout -text -noout 2>&1 | Where-Object { $_ -is [string] }
$pubHex = ""
$capture = $false
foreach ($line in $pubText) {
    if ($line -match "pub:") { $capture = $true; continue }
    if ($line -match "ASN1") { $capture = $false; continue }
    if ($capture) {
        $pubHex += ($line -replace '[\s:]', '')
    }
}

Remove-Item $tempFile -Force

# hex -> base64
$privBytes = [byte[]]::new($privHex.Length / 2)
for ($i = 0; $i -lt $privHex.Length; $i += 2) {
    $privBytes[$i / 2] = [Convert]::ToByte($privHex.Substring($i, 2), 16)
}
$privB64 = [Convert]::ToBase64String($privBytes)

$pubBytes = [byte[]]::new($pubHex.Length / 2)
for ($i = 0; $i -lt $pubHex.Length; $i += 2) {
    $pubBytes[$i / 2] = [Convert]::ToByte($pubHex.Substring($i, 2), 16)
}
# base64url no padding (Mihomo uses base64.RawURLEncoding)
$pubB64Url = [Convert]::ToBase64String($pubBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

# Generate short-id
$shortId = -join (1..8 | ForEach-Object { '{0:x2}' -f (Get-Random -Minimum 0 -Maximum 256) })

Write-Host "=== Reality Key Pair ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Private Key (server private_key):"
Write-Host "  $privB64"
Write-Host ""
Write-Host "Public Key (client public-key, base64url):"
Write-Host "  $pubB64Url"
Write-Host ""
Write-Host "Short ID:"
Write-Host "  $shortId"
Write-Host ""
Write-Host "=== Prism server configuration.json ===" -ForegroundColor Cyan
$conf = @"
"reality": {
    "dest": "www.microsoft.com:443",
    "server_names": ["www.microsoft.com"],
    "private_key": "$privB64",
    "short_ids": ["$shortId"]
},
"@
Write-Host $conf
Write-Host ""
Write-Host "=== Clash client reality-opts ===" -ForegroundColor Cyan
$clash = @"
reality-opts:
  public-key: "$pubB64Url"
  short-id: "$shortId"
"@
Write-Host $clash
