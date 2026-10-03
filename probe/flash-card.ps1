param(
    [Parameter(Mandatory)][string]$ImagePath,
    [Parameter(Mandatory)][string]$ExpectedSha256,
    [Parameter(Mandatory)][int]$DiskNumber,
    [Parameter(Mandatory)][string]$ExpectedSerial,
    [Parameter(Mandatory)][long]$ExpectedSize,
    [Parameter(Mandatory)][ValidatePattern('^[A-Z]$')][string]$ExpectedBootDriveLetter,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$VerifyOnly,
    [switch]$RepairBoot,
    [switch]$Eject
)
$ErrorActionPreference = 'Stop'
$progressPath = Join-Path $OutputDirectory 'flash-progress.json'
$diskStream = $null
$inputStream = $null
$volumeStreams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
function Save-Progress([string]$stage, [long]$done, [long]$total, [string]$detail = '') {
    [pscustomobject]@{ stage=$stage; bytes=$done; total=$total; detail=$detail; time=(Get-Date).ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath $progressPath
}
try {
    if ($VerifyOnly -and $RepairBoot) { throw 'Choose verification or boot repair, not both.' }
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Raw SD-card access requires Windows Administrator elevation.'
    }
    $imageFile = Get-Item -LiteralPath $ImagePath
    if ($imageFile.PSIsContainer -or $imageFile.Extension -ne '.img') { throw 'Expected an image file.' }
    Save-Progress 'checking-image' 0 $imageFile.Length
    $imageHash = (Get-FileHash -LiteralPath $ImagePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($imageHash -ne $ExpectedSha256.ToLowerInvariant()) { throw 'Image checksum mismatch.' }
    # Re-identify the device immediately before opening any writable handle.
    $disk = Get-Disk -Number $DiskNumber
    if ($disk.SerialNumber.Trim() -ne $ExpectedSerial -or $disk.Size -ne $ExpectedSize -or
        $disk.BusType -ne 'USB' -or $disk.IsBoot -or $disk.IsSystem -or $disk.IsReadOnly) {
        throw 'SD-card identity/safety check failed. No writes performed.'
    }
    if ($imageFile.Length -gt $disk.Size -or $imageFile.Length % 512 -ne 0) {
        throw 'Image does not fit or is not sector aligned.'
    }
    $devicePath = '\\.\PhysicalDrive' + $DiskNumber
    $buffer = New-Object byte[] 1048576
    $partitions = @(Get-Partition -DiskNumber $DiskNumber)
    if (-not $VerifyOnly -and -not $RepairBoot -and ($partitions.Count -ne 1 -or $partitions[0].DriveLetter -ne $ExpectedBootDriveLetter)) {
        throw 'Expected the specified single boot partition. Re-inspect before flashing.'
    }
    if ($VerifyOnly -or $RepairBoot) {
        if ($partitions.Count -ne 2 -or $partitions[0].DriveLetter -ne $ExpectedBootDriveLetter -or
            $partitions[0].Offset -ne 8388608 -or $partitions[0].Size -ne 536870912 -or
            $partitions[1].Offset -ne 545259520 -or $partitions[1].Size -ne 8044675072) {
            throw 'Expected the verified Raspberry Pi image partition layout.'
        }
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class CardIo {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(SafeFileHandle h, uint code,
        IntPtr input, uint inputLength, IntPtr output, uint outputLength,
        out uint returned, IntPtr overlapped);
    public static void Control(SafeFileHandle h, uint code) {
        uint returned;
        if (!DeviceIoControl(h, code, IntPtr.Zero, 0, IntPtr.Zero, 0, out returned, IntPtr.Zero))
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
    $volume = [IO.FileStream]::new(('\\.\' + $ExpectedBootDriveLetter + ':'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    $volumeStreams.Add($volume)
    [CardIo]::Control($volume.SafeFileHandle, 0x00090018) # FSCTL_LOCK_VOLUME
    [CardIo]::Control($volume.SafeFileHandle, 0x00090020) # FSCTL_DISMOUNT_VOLUME
    if (-not $VerifyOnly) {
        $diskStream = [IO.FileStream]::new($devicePath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::ReadWrite, 1048576, [IO.FileOptions]::WriteThrough)
        $inputStream = [IO.File]::OpenRead($ImagePath)
        [long]$written = 0
        [long]$writeLength = $imageFile.Length
        $writeStage = 'writing'
        if ($RepairBoot) { $writeLength = 545259520; $writeStage = 'repairing-boot' }
        Save-Progress $writeStage 0 $writeLength
        while ($written -lt $writeLength) {
            $wanted = [int][Math]::Min([long]$buffer.Length, [long]($writeLength - $written))
            $count = $inputStream.Read($buffer, 0, $wanted)
            if ($count -le 0) { throw 'Unexpected end of source image.' }
            $diskStream.Write($buffer, 0, $count)
            $written += $count
            if ($written % 67108864 -eq 0) { Save-Progress $writeStage $written $writeLength }
        }
        $diskStream.Flush($true)
        $inputStream.Dispose()
        $inputStream = $null
        $diskStream.Dispose()
    }
    $diskStream = [IO.File]::Open($devicePath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $hasher = [Security.Cryptography.SHA256]::Create()
    [long]$readBack = 0
    Save-Progress 'verifying' 0 $imageFile.Length
    while ($readBack -lt $imageFile.Length) {
        $wanted = [int][Math]::Min([long]$buffer.Length, [long]($imageFile.Length - $readBack))
        $count = $diskStream.Read($buffer, 0, $wanted)
        if ($count -le 0) { throw 'Unexpected end of card during verification.' }
        $null = $hasher.TransformBlock($buffer, 0, $count, $buffer, 0)
        $readBack += $count
        if ($readBack % 67108864 -eq 0) { Save-Progress 'verifying' $readBack $imageFile.Length }
    }
    $null = $hasher.TransformFinalBlock([byte[]]@(), 0, 0)
    $readHash = ([BitConverter]::ToString($hasher.Hash)).Replace('-', '').ToLowerInvariant()
    $hasher.Dispose()
    if ($readHash -ne $imageHash) { throw "Card readback mismatch: $readHash" }
    $diskStream.Dispose()
    $diskStream = $null
    $ejected = $false
    $ejectDetail = ''
    if ($Eject) {
        try {
            [CardIo]::Control($volume.SafeFileHandle, 0x002d4808) # IOCTL_STORAGE_EJECT_MEDIA
            $ejected = $true
        } catch { $ejectDetail = $_.Exception.Message }
    }
    foreach ($stream in $volumeStreams) { $stream.Dispose() }
    $volumeStreams.Clear()
    Update-HostStorageCache -ErrorAction SilentlyContinue
    [pscustomobject]@{ disk=$DiskNumber; serial=$ExpectedSerial; capacity=$ExpectedSize;
        imageBytes=$imageFile.Length; imageSha256=$imageHash; readbackSha256=$readHash;
        verified=$true; ejected=$ejected; ejectDetail=$ejectDetail; completed=(Get-Date).ToString('o') } |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $OutputDirectory 'flash-result.json')
    Save-Progress 'verified' $readBack $imageFile.Length $readHash
} catch {
    Save-Progress 'failed' 0 0 $_.Exception.Message
    exit 1
} finally {
    if ($inputStream) { $inputStream.Dispose() }
    if ($diskStream) { $diskStream.Dispose() }
    foreach ($stream in $volumeStreams) { $stream.Dispose() }
}
