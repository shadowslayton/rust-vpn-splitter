[CmdletBinding()]
param(
    [switch] $SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-CargoBuild {
    param(
        [Parameter(Mandatory)]
        [string] $RepositoryRoot
    )

    Push-Location -LiteralPath $RepositoryRoot
    try {
        & cargo build --release --locked
        if ($LASTEXITCODE -ne 0) {
            throw "Release build failed with exit code $LASTEXITCODE."
        }
    }
    finally {
        Pop-Location
    }
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourceExecutable = Join-Path $repositoryRoot 'target\release\rust-vpn-splitter.exe'
$sourceUninstaller = Join-Path $PSScriptRoot 'uninstall.ps1'
$installDirectory = Join-Path $env:ProgramFiles 'Rust VPN Splitter'
$installedExecutable = Join-Path $installDirectory 'rust-vpn-splitter.exe'
$installedUninstaller = Join-Path $installDirectory 'uninstall.ps1'
$startMenuShortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Rust VPN Splitter.lnk'

if (-not $SkipBuild) {
    Invoke-CargoBuild -RepositoryRoot $repositoryRoot
}

foreach ($requiredFile in @($sourceExecutable, $sourceUninstaller)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required installation file does not exist: $requiredFile"
    }
}

if (-not (Test-IsAdministrator)) {
    $powerShell = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath),
        '-SkipBuild'
    )
    $startProcessArguments = @{
        FilePath = $powerShell
        ArgumentList = $arguments
        Verb = 'RunAs'
        Wait = $true
        PassThru = $true
    }
    $elevatedProcess = Start-Process @startProcessArguments
    if ($elevatedProcess.ExitCode -ne 0) {
        throw "Elevated installation failed with exit code $($elevatedProcess.ExitCode)."
    }
    return
}

$runningProcesses = @(Get-Process -Name 'rust-vpn-splitter' -ErrorAction SilentlyContinue)
if ($runningProcesses.Count -gt 0) {
    $processIds = ($runningProcesses.Id | Sort-Object) -join ', '
    throw "Close Rust VPN Splitter before installing. Running process IDs: $processIds"
}

New-Item -ItemType Directory -Path $installDirectory -Force | Out-Null
Copy-Item -LiteralPath $sourceExecutable -Destination $installedExecutable -Force
Copy-Item -LiteralPath $sourceUninstaller -Destination $installedUninstaller -Force

$shortcutShell = New-Object -ComObject WScript.Shell
$shortcut = $shortcutShell.CreateShortcut($startMenuShortcut)
$shortcut.TargetPath = $installedExecutable
$shortcut.WorkingDirectory = $installDirectory
$shortcut.IconLocation = "$installedExecutable,0"
$shortcut.Description = 'VPN 分流管理器'
$shortcut.Save()

$sourceHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceExecutable).Hash
$installedHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $installedExecutable).Hash
if ($sourceHash -ne $installedHash) {
    throw 'Installed executable hash does not match the release build.'
}
if (-not (Test-Path -LiteralPath $startMenuShortcut -PathType Leaf)) {
    throw "Start menu shortcut was not created: $startMenuShortcut"
}

[pscustomobject]@{
    InstalledExecutable = $installedExecutable
    Uninstaller = $installedUninstaller
    StartMenuShortcut = $startMenuShortcut
    SHA256Verified = $true
} | Format-List
