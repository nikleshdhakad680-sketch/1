<!-- ========================================================= -->
<!-- 🌌 GALAXYHOST VPS BOT — PREMIUM DISCORD DEPLOYMENT SYSTEM -->
<!-- ========================================================= -->

<p align="center">
  <pre>
     ██████╗  █████╗ ██╗      █████╗ ██╗  ██╗██╗   ██╗██╗  ██╗ ██████╗ ███████╗████████╗
    ██╔════╝ ██╔══██╗██║     ██╔══██╗██║ ██╔╝██║   ██║██║ ██╔╝██╔════╝ ██╔════╝╚══██╔══╝
    ██║  ███╗███████║██║     ███████║█████╔╝ ██║   ██║█████╔╝ ██║  ███╗█████╗     ██║   
    ██║   ██║██╔══██║██║     ██╔══██║██╔═██╗ ██║   ██║██╔═██╗ ██║   ██║██╔══╝     ██║   
    ╚██████╔╝██║  ██║███████╗██║  ██║██║  ██╗╚██████╔╝██║  ██╗╚██████╔╝███████╗   ██║   
     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
  </pre>
</p>

<p align="center">
  <b>Next-Generation Discord VPS Deployment Bot</b><br>
  Create, manage, reinstall, backup, and control fully isolated Docker VPS in seconds.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Discord.py-2.3+-purple?style=for-the-badge">
  <img src="https://img.shields.io/badge/Docker-Supported-informational?style=for-the-badge">
  <img src="https://img.shields.io/badge/GalaxyHost-Premium-darkviolet?style=for-the-badge">
</p>

---

# 🌟 **What is GalaxyHost VPS Bot?**

GalaxyHost is a **fully automated VPS hosting bot** that creates real Docker-based virtual servers directly from Discord.

It supports:

✔ 6+ Operating Systems  
✔ Automatic SSH setup  
✔ Auto-TMATE live terminal sharing  
✔ Restart, Rebuild, Rename, Stats  
✔ Backup & Restore  
✔ Per-user container isolation  
✔ Full admin panel  
✔ 24/7 systemd service  

---

# 🚀 **Features**

### ⭐ Deployment Features
- OS selection menu (Ubuntu, Debian, Alpine, etc.)
- Automatic Docker image build
- Random SSH port assignment
- Auto-generated root password
- TMATE instant connection session
- Container resource limits (RAM, CPU)

### ⭐ User Management Panel
Buttons included:

| Button | Function |
|--------|----------|
| ▶️ Start | Start VPS |
| ⏹️ Stop | Stop VPS |
| 🔄 Restart | Restart VPS |
| 🛠️ Reinstall | Rebuild with new OS |
| ✏️ Rename | Rename VPS |
| ➕ Add Port | Add forwarded port |
| 🔑 SSH | Display SSH command |
| 🟣 TMATE | Create tmate share link |
| 📊 Stats | Show live container stats |

### ⭐ Backup System
- `!backup <container>`
- `!backup-list <container>`
- `!restore <container> <file>`

### ⭐ Admin Commands
- `!list-vps`
- `!remove <container>`
- Admin-only `!create`

---

# 🔧 **System Requirements**

| Component | Minimum |
|----------|---------|
| OS | Ubuntu / Debian |
| Python | 3.10+ |
| Docker | Installed & running |
| RAM | 1GB+ |
| Disk | 10GB+ |

---

# 📦 **Installation**

### 1️⃣ Clone Repository
```bash
git clone https://github.com/yourname/GalaxyHost-Bot
cd GalaxyHost-Bot
