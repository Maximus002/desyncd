#Requires -Version 5.1
<#
.SYNOPSIS
    desyncd installer/updater for Windows.

.DESCRIPTION
    Installs Rust (if missing), clones/updates desyncd, builds it,
    and optionally runs auto-adaptation.

.PARAMETER Adapt
    Run auto-adaptation after install (Russia preset).

.PARAMETER Gui
    Also build the Tauri GUI (requires Node.js 18+).

.PARAMETER Uninstall
    Remove desyncd.

.EXAMPLE
    .\install.ps1
    .\install.ps1 -Adapt
    .\install.ps1 -Gui
    .\install.ps1 -Uninstall
#>

param(
    [switch]$Adapt,
    [switch]$Gui,
    [switch]$Uninstall,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

$REPO = "https://github.com/Maximus002/desyncd.git"
$INSTALL_DIR = "$env:LOCALAPPDATA\desyncd"
$BIN_DIR = "$INSTALL_DIR\bin"
$BIN = "$BIN_DIR\desyncd.exe"
$CONFIG_DIR = "$env:APPDATA\desyncd"

function Write-Info  { Write-Host "[*] $args" -ForegroundColor Cyan }
function Write-Ok    { Write-Host "[+] $args" -ForegroundColor Green }
function Write-Warn  { Write-Host "[!] $args" -ForegroundColor Yellow }
function Write-Err   { Write-Host "[x] $args" -ForegroundColor Red; exit 1 }

# ── Help ───────────────────────────────────────────────────────────────

if ($Help) {
    Write-Host @"

desyncd installer for Windows

Usage:
    .\install.ps1              Install or update (CLI only)
    .\install.ps1 -Adapt       Install + auto-adapt (Russia preset)
    .\install.ps1 -Gui         Install CLI + build Tauri GUI (needs Node.js 18+)
    .\install.ps1 -Uninstall   Remove desyncd

"@
    exit 0
}

# ── Uninstall ──────────────────────────────────────────────────────────

if ($Uninstall) {
    Write-Info "Uninstalling desyncd..."

    # Remove from user PATH.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -like "*$BIN_DIR*") {
        $newPath = ($userPath.Split(';') | Where-Object { $_ -ne $BIN_DIR }) -join ';'
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Info "Removed $BIN_DIR from PATH"
    }

    if (Test-Path $INSTALL_DIR) {
        Remove-Item -Recurse -Force $INSTALL_DIR
    }

    Write-Ok "Removed $INSTALL_DIR"
    Write-Info "Config preserved at $CONFIG_DIR (delete manually if needed)"
    exit 0
}

# ── Main ───────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "desyncd installer" -ForegroundColor White
Write-Host ""

# ── Check/install Rust ─────────────────────────────────────────────────

function Ensure-Rust {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) {
        $ver = & rustc --version 2>&1
        Write-Ok "Rust found: $ver"
        return
    }

    Write-Warn "Rust not found. Installing via rustup..."

    $rustupInit = "$env:TEMP\rustup-init.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://win.rustup.rs/x86_64" -OutFile $rustupInit -UseBasicParsing
    } catch {
        Write-Err "Failed to download rustup. Install manually: https://rustup.rs"
    }

    & $rustupInit -y --quiet 2>&1 | Out-Null
    Remove-Item -Force $rustupInit -ErrorAction SilentlyContinue

    # Refresh PATH for this session.
    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) {
        Write-Err "Rust installation failed. Install manually: https://rustup.rs"
    }

    Write-Ok "Rust installed: $(& rustc --version)"
}

# ── Check git ──────────────────────────────────────────────────────────

function Check-Git {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err @"
git is required. Install it:
  winget install Git.Git
  # or download from https://git-scm.com/download/win
"@
    }
}

# ── Check Node.js (GUI build only) ─────────────────────────────────────
#
# Tauri's frontend build shells out to `npm` / `node`, which aren't part of
# Windows by default. Without this check, `cargo tauri build` fails deep
# inside a Vite invocation with a confusing error. Fail loudly up-front
# with a fix-it command instead.

function Check-Node {
    $node = Get-Command node -ErrorAction SilentlyContinue
    $npm  = Get-Command npm  -ErrorAction SilentlyContinue

    if (-not $node -or -not $npm) {
        Write-Err @"
Node.js 18+ is required for building the GUI. Install it:
  winget install OpenJS.NodeJS.LTS
  # or download from https://nodejs.org/

After installing, re-open the terminal and run again:
  .\install.ps1 -Gui
"@
    }

    # Sanity-check the version — Tauri v2 requires Node 18+.
    $nodeVer = (& node --version) -replace '^v',''
    $major = [int]($nodeVer.Split('.')[0])
    if ($major -lt 18) {
        Write-Err "Node.js $nodeVer is too old; Tauri v2 needs 18+. Upgrade: winget install OpenJS.NodeJS.LTS"
    }
    Write-Ok "Node.js found: v$nodeVer"
}

# ── Clone or update ────────────────────────────────────────────────────

function Fetch-Source {
    $srcDir = "$INSTALL_DIR\src"

    if (Test-Path "$srcDir\.git") {
        Write-Info "Updating existing installation..."
        Push-Location $srcDir
        & git pull --ff-only origin main 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "git pull failed, doing clean fetch"
            & git fetch origin main
            & git reset --hard origin/main
        }
        Pop-Location
    } else {
        if (Test-Path $srcDir) {
            Remove-Item -Recurse -Force $srcDir
        }
        Write-Info "Cloning desyncd..."
        New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null
        & git clone --depth 1 $REPO $srcDir
    }

    Write-Ok "Source ready"
}

# ── Build ──────────────────────────────────────────────────────────────

function Build-Desyncd {
    $srcDir = "$INSTALL_DIR\src"
    Push-Location $srcDir

    Write-Info "Building desyncd (release mode)... This may take a few minutes on first run."

    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
    & cargo build --release --bin desyncd 2>&1 | Select-Object -Last 3

    New-Item -ItemType Directory -Path $BIN_DIR -Force | Out-Null
    Copy-Item -Force "target\release\desyncd.exe" $BIN

    Pop-Location
    Write-Ok "Built and installed to $BIN"
}

# ── Build GUI (Tauri) ──────────────────────────────────────────────────
#
# The GUI is a separate build pipeline: Vite bundles the Svelte frontend,
# Tauri then wraps it into a native window. Both stages need Node/npm.
# `cargo tauri build` handles invoking `npm install` + Vite automatically.

function Build-Gui {
    $srcDir = "$INSTALL_DIR\src"
    Push-Location $srcDir

    Write-Info "Building desyncd GUI (Tauri)... This will install npm dependencies on first run."

    $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"

    # Ensure tauri-cli is available.
    $tauri = & cargo tauri --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Info "Installing tauri-cli..."
        & cargo install tauri-cli --version "^2" 2>&1 | Select-Object -Last 3
        if ($LASTEXITCODE -ne 0) {
            Pop-Location
            Write-Err "Failed to install tauri-cli"
        }
    }

    Push-Location "crates\desyncd-gui"
    & cargo tauri build 2>&1 | Select-Object -Last 5
    $tauriExit = $LASTEXITCODE
    Pop-Location

    if ($tauriExit -ne 0) {
        Pop-Location
        Write-Err "GUI build failed (exit $tauriExit)"
    }

    Pop-Location
    Write-Ok "GUI built (see target\release\bundle\ for installers)"
}

# ── Add to PATH ────────────────────────────────────────────────────────

function Ensure-Path {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$BIN_DIR*") {
        [Environment]::SetEnvironmentVariable("Path", "$BIN_DIR;$userPath", "User")
        $env:PATH = "$BIN_DIR;$env:PATH"
        Write-Info "Added $BIN_DIR to user PATH"
    }
}

# ── Auto-adapt ─────────────────────────────────────────────────────────

function Run-Adapt {
    Write-Info "Running auto-adaptation (Russia preset)..."
    Write-Info "This will probe blocked domains and find the best bypass strategy."
    Write-Host ""
    & $BIN adapt --preset russia --morphing --save 2>&1
    Write-Host ""
    Write-Ok "Adaptation complete!"
}

# ── Print usage ────────────────────────────────────────────────────────

function Print-Usage {
    Write-Host ""
    Write-Host "=== desyncd installed ===" -ForegroundColor White
    Write-Host ""
    Write-Host "  Quick start:"
    Write-Host "    desyncd adapt --preset russia --morphing --save" -ForegroundColor Green
    Write-Host "    desyncd run" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Then set SOCKS5 proxy: 127.0.0.1:1080"
    Write-Host ""
    Write-Host "  More commands:"
    Write-Host "    desyncd adapt --domain example.com --save"
    Write-Host "    desyncd test --domain example.com --all-techniques"
    Write-Host "    desyncd show-config"
    Write-Host ""
    Write-Host "  Update:     .\install.ps1"
    Write-Host "  Uninstall:  .\install.ps1 -Uninstall"
    Write-Host ""
}

# ── Run ────────────────────────────────────────────────────────────────

Check-Git
Ensure-Rust
if ($Gui) {
    # Fail fast on missing Node before we waste time cloning + building the CLI.
    Check-Node
}
Fetch-Source
Build-Desyncd
Ensure-Path

if ($Gui) {
    Build-Gui
}

if ($Adapt) {
    Run-Adapt
}

Print-Usage
Write-Ok "Done!"
