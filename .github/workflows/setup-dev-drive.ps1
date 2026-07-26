$ErrorActionPreference = 'Stop'

if ($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'NVMe setup requires a GitHub-hosted Windows runner.'
}

if (-not $env:GITHUB_WORKSPACE -or -not $env:GITHUB_ENV -or -not $env:GITHUB_PATH -or -not $env:RUNNER_TEMP) {
    throw 'The runner workspace and environment file paths must be set.'
}

if (Get-ChildItem -LiteralPath $env:GITHUB_WORKSPACE -Force | Select-Object -First 1) {
    throw 'The workspace must be empty before NVMe setup and checkout.'
}

# D: is already excluded from Defender scanning on the Windows Arm runner image.
# Select only an unused local disk; disk numbers can vary between runner hosts.
if (Get-PSDrive -Name D -ErrorAction SilentlyContinue) {
    throw 'D: is already in use; cannot configure the NVMe Dev Drive.'
}

$disks = @(Get-Disk | Where-Object {
    $_.PartitionStyle -eq 'RAW' -and
    -not $_.IsBoot -and
    -not $_.IsSystem -and
    $_.NumberOfPartitions -eq 0 -and
    $_.Size -ge 50GB -and
    ($_.BusType -eq 'NVMe' -or $_.FriendlyName -match 'NVMe')
})

if ($disks.Count -ne 1) {
    Get-Disk | Format-Table Number, FriendlyName, BusType, PartitionStyle, Size
    throw "Expected one unused NVMe disk; found $($disks.Count)."
}

$disk = $disks[0]
Write-Output "Using NVMe disk $($disk.Number): $($disk.FriendlyName), $($disk.Size / 1GB) GiB"
if ($disk.IsOffline) {
    Set-Disk -Number $disk.Number -IsOffline $false
}
if ($disk.IsReadOnly) {
    Set-Disk -Number $disk.Number -IsReadOnly $false
}

Initialize-Disk -Number $disk.Number -PartitionStyle GPT -PassThru |
    New-Partition -DriveLetter D -UseMaximumSize |
    Format-Volume -FileSystem ReFS -DevDrive -NewFileSystemLabel DevDrive -Confirm:$false -Force |
    Out-Null

fsutil devdrv trust D:
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to trust the NVMe Dev Drive.'
}
fsutil devdrv query D:
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to verify the NVMe Dev Drive.'
}

Get-Volume -DriveLetter D | Format-Table DriveLetter, FileSystem, Size, SizeRemaining

New-Item -ItemType Directory -Force -Path 'D:\workspace', 'D:\temp', 'D:\.cargo\bin', 'D:\.rustup' |
    Out-Null

# Leave the empty workspace before replacing it with a junction to the NVMe disk.
Set-Location -LiteralPath $env:RUNNER_TEMP
[Environment]::CurrentDirectory = $env:RUNNER_TEMP
Remove-Item -LiteralPath $env:GITHUB_WORKSPACE -Force
New-Item -ItemType Junction -Path $env:GITHUB_WORKSPACE -Target 'D:\workspace' |
    Out-Null

# Use the physical path so tools that stage files beside the workspace stay on NVMe.
@(
    'DEV_DRIVE=D:'
    'DEV_DRIVE_WORKSPACE=D:\workspace'
    'CARGO_HOME=D:\.cargo'
    'CARGO_TARGET_DIR=D:\workspace\target'
    'RUSTUP_HOME=D:\.rustup'
    'TEMP=D:\temp'
    'TMP=D:\temp'
    'BUN_INSTALL_CACHE_DIR=D:\.bun\install\cache'
    'npm_config_cache=D:\.npm'
) | Add-Content -LiteralPath $env:GITHUB_ENV -Encoding utf8
'D:\.cargo\bin' | Add-Content -LiteralPath $env:GITHUB_PATH -Encoding utf8
