#!/usr/bin/env sh
set -eu

REPO_URL='https://github.com/Ozag-Labs/SecureGitX.git'
REPO_REF='main'  
PACKAGE='securegitx'
MIN_PYTHON='3.10'

INSTALL_BASE="${XDG_DATA_HOME:-$HOME/.local/share}/securegitx"
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
VENV_DIR="$INSTALL_BASE/venv"
SOURCE="git+${REPO_URL}@${REPO_REF}"

_err() { printf '[error] %s\n' "$1" >&2; exit 1; }
_info() { printf '[info]  %s\n' "$1"; }
_ok()   { printf '[ok]    %s\n' "$1"; }
_warn() { printf '[warn]  %s\n' "$1" >&2; }

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

os_id() {
    if [ -r /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        printf '%s\n' "${ID:-linux}"
    else
        printf '%s\n' "linux"
    fi
}

python_help() {
    case "$(os_id)" in
        ubuntu|debian|linuxmint|pop|elementary)
            cat <<'EOF'
Install Python 3.10+ with:
  sudo apt update
  sudo apt install python3 python3-venv python3-pip
EOF
            ;;
        fedora)
            cat <<'EOF'
Install Python 3.10+ with:
  sudo dnf install python3 python3-pip python3-virtualenv
EOF
            ;;
        arch|manjaro)
            cat <<'EOF'
Install Python with:
  sudo pacman -S python python-pip
EOF
            ;;
        alpine)
            cat <<'EOF'
Install Python with:
  sudo apk add python3 py3-pip
EOF
            ;;
        *)
            cat <<'EOF'
Install Python 3.10+ from your package manager or from python.org, then rerun this script.
EOF
            ;;
    esac
}

pip_help() {
    cat <<EOF
pip was not available for the detected Python.

Try:
  $PYTHON -m ensurepip --upgrade

If that still fails, install pip through your package manager, then rerun.
EOF
}

pipx_help() {
    cat <<EOF
pipx is not installed.

You can install it with:
  $PYTHON -m pip install --user pipx
  \$HOME/.local/bin/pipx ensurepath

This installer will continue with a virtualenv fallback.
EOF
}

version_ge_310() {
    major=$1
    minor=$2
    [ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 10 ]; }
}

find_python() {
    for cmd in python3.12 python3.11 python3.10 python3; do
        if have_cmd "$cmd"; then
            ver=$("$cmd" -c 'import sys; print("%d %d" % sys.version_info[:2])' 2>/dev/null || true)
            set -- $ver
            major=${1:-0}
            minor=${2:-0}
            if version_ge_310 "$major" "$minor"; then
                printf '%s\n' "$cmd"
                return 0
            fi
        fi
    done
    return 1
}

ensure_pip() {
    if "$PYTHON" -m pip --version >/dev/null 2>&1; then
        return 0
    fi

    _info "pip was not found for $("$PYTHON" --version 2>&1). Trying automatic bootstrap."
    if "$PYTHON" -m ensurepip --upgrade >/dev/null 2>&1; then
        _ok "pip is ready."
        return 0
    fi

    _warn "Automatic pip bootstrap failed."
    pip_help
    return 1
}

install_with_pipx() {
    if ! have_cmd pipx; then
        return 1
    fi

    _info "Installing $PACKAGE with pipx."
    if pipx install --force --python "$PYTHON" "$SOURCE"; then
        return 0
    fi

    _warn "pipx install failed. Falling back to a virtual environment."
    return 1
}

install_with_venv() {
    _info "Creating isolated virtual environment."
    "$PYTHON" -m venv "$VENV_DIR"

    VENV_PYTHON="$VENV_DIR/bin/python"
    VENV_PIP="$VENV_DIR/bin/pip"

    [ -x "$VENV_PYTHON" ] || _err "Failed to create virtual environment."

    _info "Installing $PACKAGE from GitHub."
    "$VENV_PIP" install --quiet --upgrade pip setuptools wheel
    "$VENV_PIP" install --quiet "$SOURCE"

    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/securegitx" <<EOF
#!/usr/bin/env sh
exec "$VENV_DIR/bin/securegitx" "\$@"
EOF
    chmod +x "$BIN_DIR/securegitx"
}

_info "Looking for Python 3.10+."
PYTHON=$(find_python) || {
    _err "Python >= $MIN_PYTHON is required.

$(python_help)"
}

_ok "Found Python: $("$PYTHON" --version 2>&1)"

ensure_pip || exit 1

mkdir -p "$INSTALL_BASE" "$BIN_DIR"

if install_with_pipx; then
    _ok "Installed with pipx: $PACKAGE"
else
    pipx_help
    install_with_venv
    _ok "Installed with virtualenv: $PACKAGE"
fi

if command -v securegitx >/dev/null 2>&1; then
    _ok "Installed: $(securegitx --version 2>/dev/null || printf 'securegitx')"
else
    case ":$PATH:" in
        *":$BIN_DIR:"*) ;;
        *)
            printf '\n[info] Add this to your shell profile:\n'
            printf 'export PATH="%s:$PATH"\n' "$BIN_DIR"
            ;;
    esac
fi

printf '\nQuick start:\n'
printf '  securegitx init\n'
printf '  securegitx hook install\n'
printf '  securegitx scan --staged\n'