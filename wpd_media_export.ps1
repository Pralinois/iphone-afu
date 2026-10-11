# lang: PowerShell 5.1+ (compatible Windows 10/11 sans install)
# file: wpd_media_export.ps1
# target: Windows 10/11, iPhone 16 Pro, iOS 18.4+
# deps: aucune — WPD est intégré à Windows

<#
.SYNOPSIS
    Extraction photos/vidéos iPhone via PTP/WPD — zéro trust, zéro iTunes
.DESCRIPTION
    Utilise l'interface caméra WPD (Windows Portable Devices) native.
    Ne nécessite ni pairing record ni "Trust This Computer".
    Condition : iPhone déverrouillé + "Allow" tapé une fois sur l'écran.
.PARAMETER OutputDir
    Répertoire de destination (défaut : .\iphone_photos_<timestamp>)
.PARAMETER DeviceIndex
    Index du device si plusieurs appareils connectés (défaut : 0)
.PARAMETER Extensions
    Extensions à copier (défaut : jpg,heic,mov,mp4,png,raw,dng,aae,m4v)
.PARAMETER MaxFiles
    Nombre max de fichiers (0 = tous)
.PARAMETER Resume
    Reprendre une extraction interrompue (skip fichiers déjà copiés)
.PARAMETER WaitTimeout
    Attente max du déverrouillage/Allow en secondes (défaut : 90)
.PARAMETER Yes
    Ne pas demander de confirmation avant la copie
.PARAMETER VerboseMode
    Affichage détaillé
.EXAMPLE
    .\wpd_media_export.ps1 -OutputDir .\mes_photos -Resume
#>

param(
    [string]$OutputDir    = ".\iphone_photos_$(Get-Date -Format 'yyyyMMdd_HHmmss')",
    [int]$DeviceIndex     = 0,
    [string]$Extensions   = "jpg,heic,mov,mp4,png,raw,dng,aae,m4v",
    [int]$MaxFiles        = 0,
    [switch]$Resume,
    [int]$WaitTimeout     = 90,
    [switch]$Yes,
    [switch]$VerboseMode
)

$ErrorActionPreference = "Stop"
$script:StallSeconds    = 30
$script:MaxRetries      = 3

function Write-Info  { param([string]$Message) Write-Host "[*] $Message" }
function Write-Ok    { param([string]$Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Write-Warn  { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Err   { param([string]$Message) Write-Host "[x] $Message" -ForegroundColor Red }
function Write-Debug2 {
    param([string]$Message)
    if ($VerboseMode) { Write-Host "[v] $Message" -ForegroundColor DarkGray }
}

function Get-ShellApp {
    New-Object -ComObject Shell.Application
}

function Get-WPDDevices {
    <#
    Énumère tous les devices WPD connectés via COM Shell.Application.
    Retourne liste d'objets {Name, DeviceID, Index}.
    #>
    $shell = Get-ShellApp
    $pc = $shell.NameSpace(17)   # ssfDRIVES = "Ce PC"
    if ($null -eq $pc) { return @() }
    $devices = @()
    $idx = 0
    foreach ($item in @($pc.Items())) {
        if (-not $item.IsFolder) { continue }
        if ($item.Name -match 'iPhone|Apple' -or $item.Path -match 'vid_05ac') {
            $devices += [pscustomobject]@{
                Name     = $item.Name
                DeviceID = $item.Path
                Index    = $idx
            }
            $idx++
        }
    }
    return $devices
}

function Get-DeviceItem {
    param([int]$Index = 0)
    # retourne l'item COM frais (les items COM se périment entre les polls)
    $shell = Get-ShellApp
    $pc = $shell.NameSpace(17)
    $found = @()
    foreach ($item in @($pc.Items())) {
        if (-not $item.IsFolder) { continue }
        if ($item.Name -match 'iPhone|Apple' -or $item.Path -match 'vid_05ac') {
            $found += $item
        }
    }
    if ($found.Count -eq 0) { return $null }
    if ($Index -ge $found.Count) { $Index = 0 }
    return $found[$Index]
}

function Get-DCIMNamespace {
    param($DeviceItem)
    <#
    Navigue device → storage ("Internal Storage" ou "iPhone") → DCIM.
    Retourne le namespace DCIM (COM Folder) ou $null si verrouillé/absent.
    #>
    if ($null -eq $DeviceItem) { return $null }
    $storage = $null
    $children = @($DeviceItem.GetFolder.Items())
    if ($children.Count -eq 0) { return $null }      # storage vide = verrouillé (0xfeedface)
    foreach ($child in $children) {
        if ($child.IsFolder -and $child.Name -match 'Internal Storage|iPhone|Storage') {
            $storage = $child
            break
        }
    }
    if ($null -eq $storage) {
        foreach ($child in $children) {
            if ($child.IsFolder) { $storage = $child; break }
        }
    }
    if ($null -eq $storage) { return $null }
    foreach ($c in @($storage.GetFolder.Items())) {
        if ($c.Name -eq 'DCIM') { return $c.GetFolder }
    }
    return $null
}

function Get-IPhoneDevice {
    param([int]$Index = 0, [int]$Timeout = 90)
    <#
    Retourne le device iPhone à l'index donné.
    Gère les états 1-3 (aucun device / verrouillé / Allow pas tapé).
    #>
    $deadline = (Get-Date).AddSeconds($Timeout)
    $lastState = 0
    while ($true) {
        $devices = Get-WPDDevices
        if ($devices.Count -eq 0) {
            if ($lastState -ne 1) {
                Write-Info "État 1 — aucun iPhone détecté. Branchez l'iPhone via USB."
                $lastState = 1
            }
            if ((Get-Date) -ge $deadline) {
                Write-Err "Aucun device après $Timeout s — branche l'iPhone (câble data) puis relance."
                return $null
            }
            Start-Sleep -Seconds 5
            continue
        }
        if ($devices.Count -le $Index) { $Index = 0 }
        $dev = Get-DeviceItem -Index $Index
        $dcim = Get-DCIMNamespace -DeviceItem $dev
        if ($null -ne $dcim) {
            Write-Ok "Device : $($devices[$Index].Name) — DCIM accessible"
            return $dev
        }
        if ($lastState -ne 2) {
            Write-Warn "État 2/3 — iPhone détecté mais storage vide."
            Write-Warn "  → Déverrouillez l'iPhone maintenant et tapez « Allow » sur l'écran."
            $lastState = 2
        }
        if ((Get-Date) -ge $deadline) {
            Write-Err "Timeout $Timeout s — iPhone toujours verrouillé / Allow non tapé."
            return $null
        }
        Start-Sleep -Seconds 3
    }
}

function Walk-WPDFolder {
    param($Folder)
    # walk récursif paresseux : yield d'objets {Item, Folder} via file d'attente
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($Folder)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        foreach ($it in @($current.Items())) {
            if ($it.IsFolder) {
                $queue.Enqueue($it.GetFolder)
            } else {
                [pscustomobject]@{ Item = $it }
            }
        }
    }
}

function Get-FlatFileList {
    param($DCIMNamespace)
    $files = @()
    $count = 0
    foreach ($f in Walk-WPDFolder -Folder $DCIMNamespace) {
        $count++
        if ($VerboseMode -and ($count % 100 -eq 0)) {
            Write-Debug2 "scan… $count fichiers"
        }
        $files += $f.Item
    }
    return ,$files
}

function Get-StorageInfo {
    param($DCIMNamespace)
    <#
    Compte le nombre de fichiers et la taille totale dans DCIM.
    #>
    $count = 0
    [long]$bytes = 0
    $subs = 0
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($DCIMNamespace)
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        foreach ($it in @($current.Items())) {
            if ($it.IsFolder) {
                $subs++
                $queue.Enqueue($it.GetFolder)
            } else {
                $count++
                $size = $it.ExtendedProperty("System.Size")
                if ($null -ne $size) { $bytes += [long]$size }
            }
        }
    }
    return [pscustomobject]@{ FileCount = $count; TotalBytes = $bytes; SubFolders = $subs }
}

function Show-Progress {
    param([int]$Current, [int]$Total, [string]$FileName, [long]$Bytes)
    $pct = if ($Total -gt 0) { [math]::Min(100, [int](100 * $Current / $Total)) } else { 0 }
    Write-Progress -Activity "Extraction PTP" `
        -Status "[$Current/$Total] $FileName ($([math]::Round($Bytes/1MB,1)) MB)" `
        -PercentComplete $pct
    Write-Host ("  [{0}/{1}] {2} ({3} MB)" -f $Current, $Total, $FileName, [math]::Round($Bytes/1MB,1))
}

function Copy-MediaFiles {
    param(
        $DCIMNamespace,
        [string]$OutputDir,
        [string[]]$Extensions,
        [int]$MaxFiles,
        [switch]$Resume
    )
    <#
    Walk récursif DCIM → copie via CopyHere + attente de complétion.
    Resume : skip si déjà présent avec même taille.
    Stall : pas de progression 30s → retry (3x) puis skip + errors.txt.
    #>
    $stats = [pscustomobject]@{
        Copied = 0; Skipped = 0; Errors = 0; TotalBytes = [long]0; FailedFiles = @()
    }
    $all = Get-FlatFileList -DCIMNamespace $DCIMNamespace
    $media = @($all | Where-Object {
        $ext = [IO.Path]::GetExtension($_.Name).TrimStart('.').ToLower()
        $Extensions -contains $ext
    })
    $total = $media.Count
    if ($MaxFiles -gt 0 -and $total -gt $MaxFiles) { $total = $MaxFiles }

    $destShell = Get-ShellApp
    $errorsFile = Join-Path $OutputDir "errors.txt"
    $i = 0
    foreach ($item in $media) {
        if ($MaxFiles -gt 0 -and $i -ge $MaxFiles) { break }
        $i++
        $size = $item.ExtendedProperty("System.Size")
        if ($null -eq $size) { $size = 0 }
        [long]$size = $size
        # structure : on plat le mapping sous OutputDir (le walk perd le parent → nom unique suffit,
        # les noms iPhone IMG_xxxx sont uniques ; sinon suffixe compteur)
        $destPath = Join-Path $OutputDir $item.Name
        $dup = 1
        while ((Test-Path $destPath) -and -not $Resume) {
            $destPath = Join-Path $OutputDir ([IO.Path]::GetFileNameWithoutExtension($item.Name) + "_$dup" + [IO.Path]::GetExtension($item.Name))
            $dup++
        }

        if ($Resume -and (Test-Path $destPath)) {
            $localSize = (Get-Item $destPath).Length
            if ($localSize -eq $size) {
                $stats.Skipped++
                $stats.TotalBytes += $size
                Write-Debug2 "skip (déjà présent) : $($item.Name)"
                continue
            }
            Remove-Item $destPath -Force -ErrorAction SilentlyContinue
        }

        Show-Progress -Current $i -Total $total -FileName $item.Name -Bytes $stats.TotalBytes
        $copied = $false
        for ($attempt = 1; $attempt -le $script:MaxRetries -and -not $copied; $attempt++) {
            try {
                $destFolder = $destShell.NameSpace($OutputDir)
                # 1556 = 4 (no progress dlg) + 16 (yes to all) + 512 (no confirm dir) + 1024 (no UI on error)
                $destFolder.CopyHere($item, 1556)
                # attente de complétion : taille identique + stable
                $watch = [Diagnostics.Stopwatch]::StartNew()
                $lastLen = -1
                $lastChange = [Diagnostics.Stopwatch]::StartNew()
                while ($true) {
                    Start-Sleep -Milliseconds 800
                    $len = -1
                    if (Test-Path $destPath) { $len = (Get-Item $destPath).Length }
                    if ($len -ne $lastLen) {
                        $lastLen = $len
                        $lastChange.Restart()
                    }
                    if ($size -gt 0 -and $len -eq $size) { $copied = $true; break }
                    if ($size -eq 0 -and $len -ge 0 -and $lastChange.Elapsed.TotalSeconds -gt 2) { $copied = $true; break }
                    if ($lastChange.Elapsed.TotalSeconds -gt $script:StallSeconds) {
                        $stallMsg = "État 5 — pas de progression depuis $($script:StallSeconds)s sur $($item.Name) " +
                                    "(iPhone reverrouillé ?) — retry $attempt/$($script:MaxRetries)"
                        Write-Warn $stallMsg
                        break
                    }
                    if ($watch.Elapsed.TotalMinutes -gt 30) { break }   # garde-fou fichiers énormes
                }
            } catch {
                Write-Debug2 "CopyHere exception ($($item.Name)) : $_"
            }
            if (-not $copied -and $attempt -lt $script:MaxRetries) {
                Remove-Item $destPath -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        }
        if ($copied) {
            $stats.Copied++
            $stats.TotalBytes += $size
        } else {
            $stats.Errors++
            $stats.FailedFiles += $item.Name
            Add-Content -Path $errorsFile -Value "$($item.Name)`tcopy failed after $($script:MaxRetries) attempts" -Encoding UTF8
            Write-Err "Échec : $($item.Name) (log → errors.txt)"
        }
    }
    Write-Progress -Activity "Extraction PTP" -Completed
    return $stats
}

function Write-Manifest {
    param([string]$OutputDir)
    $entries = @()
    foreach ($f in (Get-ChildItem -Path $OutputDir -Recurse -File -ErrorAction SilentlyContinue)) {
        if ($f.Name -in @("manifest.json", "errors.txt", "extraction.json")) { continue }
        $entries += [pscustomobject]@{
            path       = $f.FullName.Substring((Resolve-Path $OutputDir).Path.Length + 1).Replace('\', '/')
            size_bytes = $f.Length
            mtime      = $f.LastWriteTime.ToString("yyyy-MM-ddTHH:mm:ss")
            ext        = $f.Extension.ToLower()
            exif_date  = $null
        }
    }
    $manifest = $entries | Sort-Object mtime -Descending
    $out = Join-Path $OutputDir "manifest.json"
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -Path $out -Encoding UTF8
    return $out
}

# ─── Flow principal ─────────────────────────────────────────────────────────

Write-Host ""
Write-Host "iPhone AFU — Extraction PTP/WPD (zéro trust, zéro iTunes)" -ForegroundColor Cyan
Write-Host ""

$device = Get-IPhoneDevice -Index $DeviceIndex -Timeout $WaitTimeout
if ($null -eq $device) { exit 1 }

$dcim = Get-DCIMNamespace -DeviceItem $device
if ($null -eq $dcim) { Write-Err "DCIM introuvable — reverrouillez/déverrouillez et relance."; exit 1 }

Write-Info "Analyse du stockage…"
$info = Get-StorageInfo -DCIMNamespace $dcim
Write-Ok ("État 4 — Accès DCIM confirmé : {0} fichiers, {1} GB ({2} sous-dossiers)" -f `
    $info.FileCount, [math]::Round($info.TotalBytes/1GB, 2), $info.SubFolders)

if (-not $Yes) {
    $confirm = Read-Host ("Extraire vers {0} ? [O/n]" -f $OutputDir)
    if ($confirm -eq 'n') { Write-Info "Annulé."; exit 0 }
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
$extList = $Extensions.Split(',') | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ }

$sw = [Diagnostics.Stopwatch]::StartNew()
$stats = Copy-MediaFiles -DCIMNamespace $dcim -OutputDir $OutputDir `
    -Extensions $extList -MaxFiles $MaxFiles -Resume:$Resume
$sw.Stop()

$manifestPath = Write-Manifest -OutputDir $OutputDir

Write-Host ""
Write-Host "Extraction terminée" -ForegroundColor Green
Write-Host "  Copiés  : $($stats.Copied)"
Write-Host "  Skippés : $($stats.Skipped)"
Write-Host "  Erreurs : $($stats.Errors)"
Write-Host "  Total   : $([math]::Round($stats.TotalBytes/1GB,2)) GB"
Write-Host "  Durée   : $([math]::Round($sw.Elapsed.TotalSeconds,1)) s"
Write-Host "  Dossier : $OutputDir"
Write-Host "  Manifest: $manifestPath"
if ($stats.Errors -gt 0) {
    Write-Host "  Échecs  : $($stats.FailedFiles -join ', ')" -ForegroundColor Yellow
    Write-Host "  → relance avec -Resume pour ne reprendre que les manquants" -ForegroundColor Yellow
}
