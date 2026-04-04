#!/usr/bin/env bash
#
# desyncd installer/updater — macOS & Linux
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Maximus002/desyncd/main/install.sh | bash
#   # or
#   ./install.sh              # install/update
#   ./install.sh --adapt      # install + auto-adapt (Russia preset)
#   ./install.sh --uninstall  # remove desyncd

set -euo pipefail

REPO="https://github.com/Maximus002/desyncd.git"
INSTALL_DIR="$HOME/.local/share/desyncd"
BIN_DIR="$HOME/.local/bin"
BIN="$BIN_DIR/desyncd"
CONFIG_DIR="$HOME/.config/desyncd"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[x]${NC} $*"; exit 1; }

# ── Detect OS ──────────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux*)  OS="linux" ;;
        Darwin*) OS="macos" ;;
        *)       err "Unsupported OS: $(uname -s). Use install.ps1 for Windows." ;;
    esac
    ARCH="$(uname -m)"
    info "Detected: ${BOLD}$OS${NC} ($ARCH)"
}

# ── Check/install Rust ─────────────────────────────────────────────────

ensure_rust() {
    if command -v cargo &>/dev/null; then
        local ver
        ver=$(rustc --version | awk '{print $2}')
        ok "Rust found: $ver"
        return
    fi

    warn "Rust not found. Installing via rustup..."
    if command -v curl &>/dev/null; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    elif command -v wget &>/dev/null; then
        wget -qO- https://sh.rustup.rs | sh -s -- -y --quiet
    else
        err "Neither curl nor wget found. Install Rust manually: https://rustup.rs"
    fi

    # Source cargo env for this session.
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env" 2>/dev/null || true
    export PATH="$HOME/.cargo/bin:$PATH"

    if ! command -v cargo &>/dev/null; then
        err "Rust installation failed. Install manually: https://rustup.rs"
    fi

    ok "Rust installed: $(rustc --version | awk '{print $2}')"
}

# ── Check system dependencies ──────────────────────────────────────────

check_deps() {
    if ! command -v git &>/dev/null; then
        err "git is required. Install it first:
  macOS: xcode-select --install
  Debian/Ubuntu: sudo apt install git
  Fedora: sudo dnf install git"
    fi

    # On Linux, we need build essentials for SQLite/OpenSSL.
    if [ "$OS" = "linux" ]; then
        local missing=()
        command -v cc &>/dev/null || missing+=("build-essential / gcc")
        # Check for pkg-config (needed for some native deps).
        command -v pkg-config &>/dev/null || missing+=("pkg-config")

        if [ ${#missing[@]} -gt 0 ]; then
            warn "Missing build dependencies: ${missing[*]}"
            echo "  Debian/Ubuntu: sudo apt install build-essential pkg-config"
            echo "  Fedora:        sudo dnf install gcc pkg-config"
            echo "  Arch:          sudo pacman -S base-devel pkgconf"
            echo ""
            read -rp "Continue anyway? [y/N] " yn
            [[ "$yn" =~ ^[Yy] ]] || exit 1
        fi
    fi
}

# ── Clone or update ────────────────────────────────────────────────────

fetch_source() {
    mkdir -p "$(dirname "$INSTALL_DIR")"

    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Updating existing installation..."
        cd "$INSTALL_DIR"
        git pull --ff-only origin main 2>/dev/null || {
            warn "git pull failed, doing clean fetch"
            git fetch origin main
            git reset --hard origin/main
        }
    else
        if [ -d "$INSTALL_DIR" ]; then
            warn "Directory $INSTALL_DIR exists but is not a git repo. Removing..."
            rm -rf "$INSTALL_DIR"
        fi
        info "Cloning desyncd..."
        git clone --depth 1 "$REPO" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

    local ver
    ver=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/')
    ok "Source ready: v${ver}"
}

# ── Build ──────────────────────────────────────────────────────────────

build() {
    cd "$INSTALL_DIR"
    info "Building desyncd (release mode)... This may take a few minutes on first run."

    export PATH="$HOME/.cargo/bin:$PATH"
    cargo build --release --bin desyncd 2>&1 | tail -3

    mkdir -p "$BIN_DIR"
    cp -f target/release/desyncd "$BIN"
    chmod +x "$BIN"

    ok "Built and installed to ${BOLD}$BIN${NC}"
}

# ── Add to PATH ────────────────────────────────────────────────────────

ensure_path() {
    if echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
        return
    fi

    local shell_rc=""
    case "${SHELL:-/bin/bash}" in
        */zsh)  shell_rc="$HOME/.zshrc" ;;
        */bash) shell_rc="$HOME/.bashrc" ;;
        */fish) shell_rc="$HOME/.config/fish/config.fish" ;;
        *)      shell_rc="$HOME/.profile" ;;
    esac

    if [ -n "$shell_rc" ] && [ -f "$shell_rc" ]; then
        if ! grep -q "$BIN_DIR" "$shell_rc" 2>/dev/null; then
            echo "" >> "$shell_rc"
            echo "# desyncd" >> "$shell_rc"
            echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$shell_rc"
            info "Added $BIN_DIR to PATH in $shell_rc"
        fi
    fi

    export PATH="$BIN_DIR:$PATH"
}

# ── Auto-adapt ─────────────────────────────────────────────────────────

run_adapt() {
    info "Running auto-adaptation (Russia preset)..."
    info "This will probe blocked domains and find the best bypass strategy."
    echo ""
    "$BIN" adapt --preset russia --morphing --save 2>&1 || {
        warn "Adaptation had issues, but config may still have been generated."
    }
    echo ""
    ok "Adaptation complete!"
}

# ── Uninstall ──────────────────────────────────────────────────────────

uninstall() {
    info "Uninstalling desyncd..."
    rm -f "$BIN"
    rm -rf "$INSTALL_DIR"
    # Don't remove config — user may want to keep it.
    ok "Removed $BIN and $INSTALL_DIR"
    info "Config preserved at $CONFIG_DIR (delete manually if needed)"
    exit 0
}

# ── Print usage info ───────────────────────────────────────────────────

print_usage() {
    echo ""
    echo -e "${BOLD}=== desyncd installed ===${NC}"
    echo ""
    echo "  Quick start:"
    echo -e "    ${GREEN}desyncd adapt --preset russia --morphing --save${NC}  # find bypass strategies"
    echo -e "    ${GREEN}desyncd run${NC}                                      # start proxy"
    echo ""
    echo "  Then set SOCKS5 proxy: 127.0.0.1:1080"
    echo ""
    echo "  More commands:"
    echo "    desyncd adapt --domain example.com --save    # adapt specific domain"
    echo "    desyncd test --domain example.com --all-techniques"
    echo "    desyncd show-config"
    echo ""
    echo "  Update:     $0"
    echo "  Uninstall:  $0 --uninstall"
    echo ""
}

# ── Main ───────────────────────────────────────────────────────────────

main() {
    echo ""
    echo -e "${BOLD}desyncd installer${NC}"
    echo ""

    # Handle flags.
    local do_adapt=false
    for arg in "$@"; do
        case "$arg" in
            --uninstall) uninstall ;;
            --adapt)     do_adapt=true ;;
            --help|-h)
                echo "Usage: $0 [--adapt] [--uninstall]"
                echo "  --adapt      Install and run auto-adaptation (Russia preset)"
                echo "  --uninstall  Remove desyncd"
                exit 0
                ;;
        esac
    done

    detect_os
    check_deps
    ensure_rust
    fetch_source
    build
    ensure_path

    if [ "$do_adapt" = true ]; then
        run_adapt
    fi

    print_usage

    ok "Done!"
}

main "$@"
