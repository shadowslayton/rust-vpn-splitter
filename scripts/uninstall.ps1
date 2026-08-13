[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$installDirectory = Join-Path $env:ProgramFiles 'Rust VPN Splitter'
$installedExecutable = Join-Path $installDirectory 'rust-vpn-splitter.exe'
$installedUninstaller = Join-Path $installDirectory 'uninstall.ps1'
$startMenuShortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Rust VPN Splitter.lnk'

if (-not (Test-IsAdministrator)) {
    $powerShell = (Get-Process -Id $PID).Path
    $arguments = @(
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath)
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
        throw "Elevated uninstallation failed with exit code $($elevatedProcess.ExitCode)."
    }
    return
}

$runningProcesses = @(Get-Process -Name 'rust-vpn-splitter' -ErrorAction SilentlyContinue)
if ($runningProcesses.Count -gt 0) {
    $processIds = ($runningProcesses.Id | Sort-Object) -join ', '
    throw "Close Rust VPN Splitter before uninstalling. Running process IDs: $processIds"
}

foreach ($path in @($startMenuShortcut, $installedExecutable, $installedUninstaller)) {
    if (Test-Path -LiteralPath $path) {
        Remove-Item -LiteralPath $path -Force
    }
}

$installDirectoryRemoved = $false
if (Test-Path -LiteralPath $installDirectory) {
    $remainingItems = @(Get-ChildItem -Force -LiteralPath $installDirectory)
    if ($remainingItems.Count -eq 0) {
        Remove-Item -LiteralPath $installDirectory
        $installDirectoryRemoved = $true
    }
}

[pscustomobject]@{
    InstalledExecutableRemoved = -not (Test-Path -LiteralPath $installedExecutable)
    StartMenuShortcutRemoved = -not (Test-Path -LiteralPath $startMenuShortcut)
    InstallDirectoryRemoved = $installDirectoryRemoved
    UserSettingsPreserved = $true
} | Format-List
