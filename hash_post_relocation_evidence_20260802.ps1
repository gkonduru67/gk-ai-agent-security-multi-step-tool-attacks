param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot,

    [Parameter(Mandatory = $true)]
    [string]$NotesRoot,

    [string]$LogsRoot = "C:\x_ai_logs"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-Sha256Manifest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EvidenceRoot,

        [Parameter(Mandatory = $true)]
        [string]$RootLabel,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (-not (Test-Path -LiteralPath $EvidenceRoot -PathType Container)) {
        throw "Evidence root does not exist: $EvidenceRoot"
    }

    if (Test-Path -LiteralPath $ManifestPath) {
        throw "Refusing to overwrite existing manifest: $ManifestPath"
    }

    $manifestDirectory = Split-Path -Parent $ManifestPath

    if (-not (Test-Path -LiteralPath $manifestDirectory)) {
        New-Item `
            -ItemType Directory `
            -Path $manifestDirectory `
            -Force |
            Out-Null
    }

    $files = @(
        Get-ChildItem `
            -LiteralPath $EvidenceRoot `
            -File `
            -Recurse |
        Where-Object {
            $_.FullName -notlike "$manifestDirectory\*" -and
            $_.Name -notlike "*sha256*.csv" -and
            $_.Name -notlike "*sha256*.json"
        } |
        Sort-Object FullName
    )

    $rows = foreach ($file in $files) {
        $relativePath = $file.FullName.Substring(
            $EvidenceRoot.Length
        ).TrimStart("\")

        $hash = Get-FileHash `
            -LiteralPath $file.FullName `
            -Algorithm SHA256

        [pscustomobject]@{
            ManifestSchema   = "POST_RELOCATION_SHA256_V1"
            EvidenceRoot     = $RootLabel
            RelativePath     = $relativePath
            LengthBytes      = $file.Length
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString("o")
            SHA256           = $hash.Hash.ToUpperInvariant()
        }
    }

    $rows |
        Export-Csv `
            -LiteralPath $ManifestPath `
            -NoTypeInformation `
            -Encoding UTF8

    $manifestHash = Get-FileHash `
        -LiteralPath $ManifestPath `
        -Algorithm SHA256

    [pscustomobject]@{
        ManifestPath   = $ManifestPath
        FilesHashed    = $rows.Count
        ManifestSHA256 = $manifestHash.Hash.ToUpperInvariant()
    }
}

function New-AuthoritativeDocumentManifest {
    param(
        [Parameter(Mandatory = $true)]
        [array]$Documents,

        [Parameter(Mandatory = $true)]
        [string]$ManifestPath
    )

    if (Test-Path -LiteralPath $ManifestPath) {
        throw "Refusing to overwrite existing manifest: $ManifestPath"
    }

    $manifestDirectory = Split-Path -Parent $ManifestPath

    if (-not (Test-Path -LiteralPath $manifestDirectory)) {
        New-Item `
            -ItemType Directory `
            -Path $manifestDirectory `
            -Force |
            Out-Null
    }

    $rows = foreach ($document in $Documents) {
        if (-not (
            Test-Path `
                -LiteralPath $document.Path `
                -PathType Leaf
        )) {
            throw "Authoritative document not found: $($document.Path)"
        }

        $file = Get-Item -LiteralPath $document.Path
        $hash = Get-FileHash `
            -LiteralPath $file.FullName `
            -Algorithm SHA256

        [pscustomobject]@{
            ManifestSchema   = "POST_RELOCATION_SHA256_V1"
            AttackFamily     = $document.AttackFamily
            Role             = "AUTHORITATIVE_DOCUMENT"
            FileName         = $file.Name
            LengthBytes      = $file.Length
            LastWriteTimeUtc = $file.LastWriteTimeUtc.ToString("o")
            SHA256           = $hash.Hash.ToUpperInvariant()
            Path             = $file.FullName
        }
    }

    $rows |
        Export-Csv `
            -LiteralPath $ManifestPath `
            -NoTypeInformation `
            -Encoding UTF8

    $manifestHash = Get-FileHash `
        -LiteralPath $ManifestPath `
        -Algorithm SHA256

    [pscustomobject]@{
        ManifestPath   = $ManifestPath
        FilesHashed    = $rows.Count
        ManifestSHA256 = $manifestHash.Hash.ToUpperInvariant()
    }
}

$DwProjectRoot = Join-Path $ProjectRoot "DW"
$CdProjectRoot = Join-Path $ProjectRoot "CD"
$DwLogsRoot    = Join-Path $LogsRoot "DW"
$CdLogsRoot    = Join-Path $LogsRoot "CD"

$DwProjectManifest = Join-Path `
    $DwProjectRoot `
    "manifests\dw_post_relocation_sha256_20260802.csv"

$CdProjectManifest = Join-Path `
    $CdProjectRoot `
    "manifests\cd_post_relocation_sha256_20260802.csv"

$DwLogsManifest = Join-Path `
    $DwLogsRoot `
    "manifests\dw_logs_post_relocation_sha256_20260802.csv"

$CdLogsManifest = Join-Path `
    $CdLogsRoot `
    "manifests\cd_logs_post_relocation_sha256_20260802.csv"

$NotesManifest = Join-Path `
    $NotesRoot `
    "manifests\authoritative_documents_sha256_20260802.csv"

$DwDocument = Join-Path `
    $NotesRoot `
    "AI_Agent_Security_Project_DESTRUCTIVE_WRITE_UPDATED.docx"

$CdDocument = Join-Path `
    $NotesRoot `
    "AI Agent Security Project Confused_deputy_UPDATED.docx"

$results = @()

$results += New-Sha256Manifest `
    -EvidenceRoot $DwProjectRoot `
    -RootLabel "DW_PROJECT" `
    -ManifestPath $DwProjectManifest

$results += New-Sha256Manifest `
    -EvidenceRoot $CdProjectRoot `
    -RootLabel "CD_PROJECT" `
    -ManifestPath $CdProjectManifest

$results += New-Sha256Manifest `
    -EvidenceRoot $DwLogsRoot `
    -RootLabel "DW_LOGS" `
    -ManifestPath $DwLogsManifest

$results += New-Sha256Manifest `
    -EvidenceRoot $CdLogsRoot `
    -RootLabel "CD_LOGS" `
    -ManifestPath $CdLogsManifest

$results += New-AuthoritativeDocumentManifest `
    -Documents @(
        @{
            AttackFamily = "DESTRUCTIVE_WRITE"
            Path         = $DwDocument
        },
        @{
            AttackFamily = "CONFUSED_DEPUTY"
            Path         = $CdDocument
        }
    ) `
    -ManifestPath $NotesManifest

Write-Host ""
Write-Host "Post-relocation SHA-256 baseline created."
Write-Host ""

$results |
    Format-Table `
        ManifestPath,
        FilesHashed,
        ManifestSHA256 `
        -AutoSize