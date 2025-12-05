#!/bin/bash
clear

# ============================================================
# 🌌 GalaxyHost Ultra Premium+ Installer v4.0
# This installer setups your Bot, Environment, Docker, Python,
# Requirements, Systemd, .env, folders, diagnostics, and more.
# ============================================================

# ---------- COLOR CODES ----------
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
WHITE="\e[97m"
RESET="\e[0m"
BOLD="\e[1m"

# ============================================================
# 🌌 ANIMATED GALAXY INTRO
# ============================================================
galaxy_intro() {
    echo -e "${MAGENTA}${BOLD}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "          🌌  GALAXYHOST PREMIUM+ INSTALLER         "
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${RESET}"

    frames=("✨" "🌙" "⭐" "🌘" "🌗" "🌖" "🌕" "🌔" "🌓" "🌒")
    echo -ne "${CYAN}Starting Installer "
    for i in {1..30}; do
        echo -n "${frames[$i % ${#frames[@]}]}"
        sleep 0.08
        echo -ne "\b"
    done
    echo -e "${RESET}\n"
}
galaxy_intro

# ============================================================
# 🔄 LOADING SPINNER FUNCTION
# ============================================================
spinner() {
    local pid=$!
    local msg=$1
    local spin='🌑🌒🌓🌔🌕🌖🌗🌘'
    local i=0

    echo -ne "${BLUE}${msg}${RESET}\n"
    while kill -0 $pid 2>/dev/null; do
        i=$(( (i+1) %8 ))
        printf "    ${spin:$i:1} Processing...\r"
        sleep 0.15
    done
    printf "    ${GREEN}✔ Completed${RESET}\n"
}

# ============================================================
# 🔧 STEP HEADER FUNCTION
# ============================================================
step() {
    echo -e "\n${YELLOW}${BOLD}[ $1 ]──────────────────────────────────────────────${RESET}"
}

# ============================================================
# 🔥 STEP 1 — SYSTEM UPDATE
# ============================================================
step "1/10 Updating System"
apt update -y >/dev/null 2>&1 &
spinner "Updating APT packages..."

# ============================================================
# 🐳 STEP 2 — INSTALL DOCKER
# ============================================================
step "2/10 Installing Docker Engine"
apt install docker.io -y >/dev/null 2>&1 &
spinner "Installing Docker..."

systemctl enable --now docker >/dev/null 2>&1

# ============================================================
# 🐍 STEP 3 — INSTALL PYTHON + PIP
# ============================================================
step "3/10 Installing Python & Pip"
apt install python3 python3-pip -y >/dev/null 2>&1 &
spinner "Installing Python3..."

# ============================================================
# 📘 STEP 4 — VERIFY & INSTALL PYTHON LIBRARIES
# ============================================================
step "4/10 Installing Python requirements"

if [[ ! -f requirements.py ]]; then
    echo -e "${RED}requirements.py is missing!${RESET}"
    echo -e "${CYAN}Create a file named requirements.py:${RESET}"
    echo 'required = ["discord.py","aiohttp","python-dotenv"]'
    exit 1
fi

REQS=$(python3 - <<EOF
import requirements
print(" ".join(requirements.required))
EOF
)

pip install $REQS >/dev/null 2>&1 &
spinner "Installing Python dependencies..."

# ============================================================
# 📂 STEP 5 — CREATE DIRECTORY STRUCTURE
# ============================================================
step "5/10 Setting Up GalaxyHost Directories"

mkdir -p /opt/galaxyhost/{logs,backups,temp} >/dev/null 2>&1 &
spinner "Preparing folders under /opt/galaxyhost..."

# ============================================================
# 🔐 STEP 6 — CREATE .env FILE (INTERACTIVE)
# ============================================================
step "6/10 Configuring .env File"

if [[ ! -f .env ]]; then
    echo -e "${CYAN}No .env found. Creating one now...${RESET}"

    read -p "→ Enter DISCORD BOT TOKEN: " TOKEN
    read -p "→ Enter MAIN_ADMIN_ID: " ADMIN

    cat <<EOF > .env
DISCORD_TOKEN=$TOKEN
MAIN_ADMIN_ID=$ADMIN
DEPLOY_ROOT=/opt/galaxyhost
DOCKER_CMD=docker
HOST_PUBLIC_IP=
EOF

    echo -e "${GREEN}✔ .env file created successfully${RESET}"
else
    echo -e "${GREEN}✔ Found existing .env, skipping creation${RESET}"
fi

# ============================================================
# 📝 STEP 7 — VERIFY BOT FILE
# ============================================================
step "7/10 Checking bot.py"

if [[ -f bot.py ]]; then
    echo -e "${GREEN}✔ bot.py Found${RESET}"
else
    echo -e "${RED}✖ bot.py Missing! Create your bot file before running.${RESET}"
    exit 1
fi

# ============================================================
# ⚙️ STEP 8 — CREATING SYSTEMD SERVICE
# ============================================================
step "8/10 Creating systemd Service (galaxybot.service)"

SERVICE_PATH="/etc/systemd/system/galaxybot.service"

cat <<EOF > $SERVICE_PATH
[Unit]
Description=GalaxyHost Discord VPS Bot
After=network.target docker.service

[Service]
User=root
WorkingDirectory=$(pwd)
EnvironmentFile=$(pwd)/.env
ExecStart=/usr/bin/python3 $(pwd)/bot.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload >/dev/null 2>&1
systemctl enable galaxybot >/dev/null 2>&1
systemctl restart galaxybot >/dev/null 2>&1

echo -e "${GREEN}✔ Systemd service installed & started${RESET}"

# ============================================================
# 🔬 STEP 9 — FULL SYSTEM DIAGNOSTIC REPORT
# ============================================================
step "9/10 Running Diagnostics"

echo -e "${CYAN}Docker Version:${RESET}"
docker --version || echo -e "${RED}Docker Error${RESET}"
echo ""

echo -e "${CYAN}Python Version:${RESET}"
python3 -V || echo -e "${RED}Python Error${RESET}"
echo ""

echo -e "${CYAN}Bot Service Status:${RESET}"
systemctl is-active galaxybot && echo -e "${GREEN}Running${RESET}" || echo -e "${RED}Not Running${RESET}"
echo ""

# ============================================================
# 🎉 STEP 10 — INSTALLATION COMPLETE
# ============================================================
step "10/10 Installation Finished!"

echo -e "${MAGENTA}${BOLD}"
echo "╔══════════════════════════════════════════════════╗"
echo "             🎉 GALAXYHOST INSTALLED! 🎉             "
echo "╠══════════════════════════════════════════════════╣"
echo "  ✔ Docker Installed                               "
echo "  ✔ Python Ready                                   "
echo "  ✔ Requirements Installed                         "
echo "  ✔ Directories Prepared                           "
echo "  ✔ .env Configured                                "
echo "  ✔ Systemd Service Running                        "
echo "╚══════════════════════════════════════════════════╝"
echo -e "${RESET}"

echo -e "${CYAN}Your bot is now live!${RESET}"
echo -e "${GREEN}To check logs:${RESET} ${YELLOW}journalctl -u galaxybot -f${RESET}"
echo -e "${GREEN}To restart bot:${RESET} ${YELLOW}systemctl restart galaxybot${RESET}"
echo ""
echo -e "${MAGENTA}${BOLD}GalaxyHost — Deploy. Automate. Dominate.${RESET}"
echo ""
