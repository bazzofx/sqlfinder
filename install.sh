#!/bin/bash

set -e

# ---------------- Check Go ----------------
if ! command -v go >/dev/null 2>&1; then
  echo "[*] Go not found. Installing GoLang..."

  sudo apt update
  sudo apt install -y golang

  # Persist environment variables
  if ! grep -q "GOROOT" ~/.bashrc; then
    cat << 'EOF' >> ~/.bashrc

# GoLang environment
export GOROOT=/usr/lib/go
export GOPATH=$HOME/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
EOF
  fi

  echo "[*] Go installed. Restart your terminal or run:"
  echo "    source ~/.bashrc"
else
  echo "[✓] Go is already installed"
fi

echo "[*] Installing katana..."
CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest

# Ensure Go bin is in PATH
export PATH="$PATH:$(go env GOPATH)/bin"

echo "[*] Installing uro..."
if ! command -v pipx >/dev/null 2>&1; then
  echo "[!] pipx not found. Installing pipx..."
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath
  export PATH="$PATH:$HOME/.local/bin"
fi

pipx install uro || pipx reinstall uro

echo "[*] Verifying installations..."

# -------- Checks --------
if ! command -v katana >/dev/null 2>&1; then
  echo "[✗] katana installation failed"
  exit 1
fi

if ! command -v uro >/dev/null 2>&1; then
  echo "[✗] uro installation failed"
  exit 1
fi

echo "[✓] katana installed: $(katana -version 2>/dev/null || echo OK)"
echo "[✓] uro installed: $(uro --help >/dev/null 2>&1 && echo OK)"

echo "done"
