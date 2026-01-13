#!/bin/bash

#!/bin/bash

# Get the current user (who invoked sudo or the script)
if [ "$EUID" -eq 0 ]; then
    # If running as root, get the original user from SUDO_USER
    if [ -n "$SUDO_USER" ]; then
        CURRENT_USER="$SUDO_USER"
    else
        # If root ran it directly without sudo, try to get from who am i
        CURRENT_USER=$(who am i | awk '{print $1}')
        if [ -z "$CURRENT_USER" ]; then
            CURRENT_USER="root"
        fi
    fi
else
    CURRENT_USER=$(whoami)
fi

CURRENT_GROUP=$(id -gn "$CURRENT_USER")
HOME_DIR=$(eval echo "~$CURRENT_USER")

echo "[*] Installing as user: $CURRENT_USER"
echo "[*] Home directory: $HOME_DIR"



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
sudo cp katana/katana /usr/local/bin/
sudo chmod 755 /usr/local/bin/katana
sudo chown "$CURRENT_USER:$CURRENT_GROUP" /usr/local/bin/katana

echo "[*] Installing uro..."
if ! command -v pipx >/dev/null 2>&1; then
    echo "[!] pipx not found. Installing pipx..."
    
    # Check if we're root or normal user
    if [ "$EUID" -eq 0 ]; then
        # Running as root, install pipx for the target user
        sudo -u "$CURRENT_USER" python3 -m pip install --user pipx
    else
        # Running as normal user
        python3 -m pip install --user pipx
    fi
    
    # Add pipx to PATH
    export PATH="$PATH:$HOME_DIR/.local/bin"
fi

# Clone and install uro
git clone https://github.com/s0md3v/uro
cd uro

# Install uro
if [ "$EUID" -eq 0 ]; then
    # As root, install for the target user
    sudo -u "$CURRENT_USER" pipx install --force uro
    # Copy the uro binary
    sudo cp "$HOME_DIR/.local/bin/uro" /usr/local/bin/
else
    # As normal user
    pipx install --force uro
    # Copy uro binary (might need sudo)
    if command -v sudo >/dev/null 2>&1; then
        sudo cp "$HOME_DIR/.local/bin/uro" /usr/local/bin/
    else
        cp "$HOME_DIR/.local/bin/uro" /usr/local/bin/
    fi
fi

# Fix permissions on uro binary
sudo chmod 755 /usr/local/bin/uro
sudo chown "$CURRENT_USER:$CURRENT_GROUP" /usr/local/bin/uro


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
clear
echo "[✓] katana installed: $(katana -version 2>/dev/null || echo OK)"
echo "[✓] uro installed: $(uro --help >/dev/null 2>&1 && echo OK)"
echo "[✓]You are all set to start using SQLFiner"

