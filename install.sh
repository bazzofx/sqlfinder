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
  # Ensure Go bin is in PATH
  export PATH="$PATH:$(go env GOPATH)/bin"
  echo "[*] Go installed. Restart your terminal or run:"
  echo "    source ~/.bashrc"
else
  echo "[✓] Go is already installed"
fi


echo "[*] Installing katana..."
wget https://github.com/projectdiscovery/katana/releases/download/v1.4.0/katana_1.4.0_linux_amd64.zip
unzip katana_1.4.0_linux_amd64.zip -d katana
cp katana/katana /usr/local/bin

echo "[*] Installing uro..."
if ! command -v pipx >/dev/null 2>&1; then
  echo "[!] pipx not found. Installing pipx..."
  python3 -m pip install --user pipx --break-system-packages
  python3 -m pipx ensurepath
  export PATH="$PATH:$HOME/.local/bin"
fi

git clone https://github.com/s0md3v/uro
cd uro/uro
pipx install uro --force
mv uro.py uro
cp uro "/usr/local/bin"

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

echo "[✓]You are all set to start using SQLFiner"
echo "done"
