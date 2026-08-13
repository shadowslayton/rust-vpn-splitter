---
name: install-release-app
description: Install or update Rust VPN Splitter on Windows from the current checkout, verify the installed executable, then run cargo clean. Use when asked to 正式安裝, 重新安裝, 更新已安裝程式, run scripts/install.ps1, or clean build artifacts after installation. Exclude MSI or distributable packaging for other machines.
---

# Install Release App

Install the current checkout through the repository's supported PowerShell installer. Clean Cargo artifacts only after the installed application has been verified.

## Workflow

1. Work from the repository root. Confirm that `Cargo.toml`, `Cargo.lock`, `scripts/install.ps1`, and `scripts/uninstall.ps1` exist.
2. Read `scripts/install.ps1` and the installation section of `README.md` before acting. Treat them as the source of truth if paths or behavior differ from this skill.
3. Run `cargo --version` and review `git status --short`. Tell the user when the current checkout contains uncommitted source or build changes because the installed binary will include them.
4. Check for a running app with `Get-Process -Name rust-vpn-splitter -ErrorAction SilentlyContinue`. If found, ask the user to close it and leave the process running until they do; do not terminate it automatically.
5. Tell the user that the installer will build the release binary and may display a Windows UAC prompt. Run:

   ```powershell
   & .\scripts\install.ps1
   ```

   Use the normal build path. Pass `-SkipBuild` only when the user explicitly requests it and `target\release\rust-vpn-splitter.exe` already exists.
6. Continue only when the installer exits successfully. Independently verify the installed files and executable hash before cleanup:

   ```powershell
   $sourceExecutable = Join-Path $PWD.Path 'target\release\rust-vpn-splitter.exe'
   $installedExecutable = Join-Path $env:ProgramFiles 'Rust VPN Splitter\rust-vpn-splitter.exe'
   $installedUninstaller = Join-Path $env:ProgramFiles 'Rust VPN Splitter\uninstall.ps1'
   $startMenuShortcut = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Rust VPN Splitter.lnk'

   foreach ($requiredFile in @($sourceExecutable, $installedExecutable, $installedUninstaller, $startMenuShortcut)) {
       if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
           throw "Required file is missing: $requiredFile"
       }
   }

   if ((Get-FileHash -Algorithm SHA256 -LiteralPath $sourceExecutable).Hash -ne
       (Get-FileHash -Algorithm SHA256 -LiteralPath $installedExecutable).Hash) {
       throw 'Installed executable hash does not match the release build.'
   }
   ```

   If installation, elevation, or verification fails, stop without cleaning `target`. Report the failing condition and preserve the build artifacts for diagnosis or retry.
7. Run `cargo clean` from the repository root.
8. Confirm that the installed executable and Start menu shortcut still exist after cleanup. Treat a cleanup failure as a cleanup error; do not roll back a successful installation.
9. Report the installed executable path, shortcut path, successful SHA-256 verification, and the `cargo clean` result.

## Boundaries

- Use this workflow only for installing the current checkout on the local Windows machine. It does not create a standalone installer for other users.
- Expect `cargo clean` to remove the repository's `target` directory. It must not remove the installed application, Start menu shortcut, Cargo registry cache, or user settings.
- Leave uninstalling and deletion from `Program Files` outside this workflow.
