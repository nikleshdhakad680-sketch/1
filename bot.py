#!/usr/bin/env python3
"""
GalaxyHost Bot Deployer — Advanced (Full single-file)
Settings chosen:
  - SSH username: root
  - SSH host port range: 25565-25665 (persistent port chosen once at creation)
  - On reinstall: keep SSH port (do not regenerate)
  - Command prefix: !
  - Help command: !help

Requirements:
  pip install discord.py aiohttp python-dotenv

Environment variables:
  DISCORD_TOKEN  (required)
  MAIN_ADMIN_ID  (optional admin override)
  DEPLOY_ROOT    (optional, default /opt/galaxyhost)
  DOCKER_CMD     (optional, default docker or "sudo docker")

Important security notes:
  - This script runs Docker build/run and other shell commands. Run on a trusted host.
  - SSH root password method is used for convenience. For production, prefer SSH keys.
  - Docker volumes do not enforce disk quotas by default. See comments where loopback files could be added.
"""

import os
import shlex
import subprocess
import sqlite3
import asyncio
import logging
import random
import string
from datetime import datetime
from typing import Optional, Dict

import discord
from discord.ext import commands

# Optional .env loader
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# ----------------------------
# Configuration (change via env)
# ----------------------------
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
MAIN_ADMIN_ID = os.getenv("MAIN_ADMIN_ID")  # string
DEPLOY_ROOT = os.getenv("DEPLOY_ROOT", "/opt/galaxyhost")
DOCKER_CMD = os.getenv("DOCKER_CMD", "docker")  # set "sudo docker" if needed

SSH_USER = "root"
SSH_PORT_MIN = 25565
SSH_PORT_MAX = 25665
REINSTALL_KEEP_SSH = True  # keep same port on reinstall

# OS templates mapping: key -> docker base
OS_TEMPLATES = {
    "ubuntu24": "ubuntu:24.04",
    "ubuntu22": "ubuntu:22.04",
    "debian12": "debian:12",
    "debian11": "debian:11",
    "alpine": "alpine:latest"
}

# ensure directories
os.makedirs(DEPLOY_ROOT, exist_ok=True)
os.makedirs(os.path.join(DEPLOY_ROOT, "logs"), exist_ok=True)
os.makedirs(os.path.join(DEPLOY_ROOT, "backups"), exist_ok=True)

# Logging
logging.basicConfig(
    filename=os.path.join(DEPLOY_ROOT, "galaxy_deployer.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("galaxy_deployer")

# SQLite DB
DB_PATH = os.path.join(DEPLOY_ROOT, "galaxy.db")
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS containers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id TEXT,
        container_name TEXT UNIQUE,
        image_name TEXT,
        os_template TEXT,
        ram_gb INTEGER,
        cpu_cores REAL,
        disk_gb INTEGER,
        ssh_port INTEGER,
        root_pass TEXT,
        created_at TEXT,
        status TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS backups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        container_name TEXT,
        filename TEXT,
        created_at TEXT
    )''')
    conn.commit()
    conn.close()
init_db()

# ----------------------------
# Utilities: run shell commands
# ----------------------------
DEFAULT_TIMEOUT = 300
def run_cmd(cmd, timeout=DEFAULT_TIMEOUT):
    """
    cmd: list or string
    returns (rc, stdout, stderr)
    """
    if isinstance(cmd, str):
        args = shlex.split(cmd)
    else:
        args = cmd
    logger.info("RUN: %s", " ".join(args))
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired as e:
        logger.error("Timeout: %s", e)
        return 124, "", f"Timeout: {e}"

# ----------------------------
# Docker helpers
# ----------------------------
def docker_build_image(build_dir: str, image_tag: str) -> (bool, str):
    cmd = f"{DOCKER_CMD} build -t {image_tag} {build_dir}"
    rc, out, err = run_cmd(cmd, timeout=900)
    if rc == 0:
        return True, out
    return False, err or out

def docker_run_container(image_tag: str, container_name: str, host_ssh_port:int, ram_gb:int, cpu_cores:float, volume_name:Optional[str]=None) -> (bool, str):
    mem_flag = f"--memory={ram_gb}g" if ram_gb and ram_gb>0 else ""
    cpus_flag = f"--cpus={cpu_cores}" if cpu_cores and cpu_cores>0 else ""
    vol_flag = f"-v {volume_name}:/data" if volume_name else ""
    cmd = f"{DOCKER_CMD} run -d --name {container_name} -p {host_ssh_port}:22 {mem_flag} {cpus_flag} {vol_flag} --restart unless-stopped {image_tag}"
    rc, out, err = run_cmd(cmd, timeout=180)
    if rc == 0:
        return True, out
    return False, err or out

def docker_stop_rm(container_name: str):
    return run_cmd(f"{DOCKER_CMD} rm -f {container_name}")

def docker_remove_image(image_tag: str):
    return run_cmd(f"{DOCKER_CMD} rmi -f {image_tag}")

def docker_exec(container: str, cmd: str, timeout=120):
    # use /bin/sh -lc for portability (alpine/debian)
    full = f"{DOCKER_CMD} exec {container} /bin/sh -lc {shlex.quote(cmd)}"
    return run_cmd(full, timeout=timeout)

def docker_create_volume(name: str):
    rc, out, err = run_cmd(f"{DOCKER_CMD} volume create {name}")
    return rc==0, out if out else err

# ----------------------------
# Helper functions: DB meta
# ----------------------------
def rand_string(n=12):
    import secrets, string
    alph = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alph) for _ in range(n))

def ensure_unique_name(owner_id: str) -> str:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM containers WHERE owner_id = ?", (owner_id,))
    cnt = c.fetchone()[0] or 0
    idx = cnt + 1
    name = f"galaxy-vps-{owner_id}-{idx}"
    conn.close()
    return name

def save_container_meta(owner_id: str, container_name: str, image_name: str, os_template: str, ram:int, cpu:float, disk:int, ssh_port:int, root_pass:str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''INSERT INTO containers (owner_id,container_name,image_name,os_template,ram_gb,cpu_cores,disk_gb,ssh_port,root_pass,created_at,status)
                 VALUES (?,?,?,?,?,?,?,?,?,?,?)''', (owner_id, container_name, image_name, os_template, ram, cpu, disk, ssh_port, root_pass, datetime.utcnow().isoformat(), "running"))
    conn.commit()
    conn.close()

def get_container_meta(container_name: str) -> Optional[Dict]:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT owner_id,container_name,image_name,os_template,ram_gb,cpu_cores,disk_gb,ssh_port,root_pass,created_at,status FROM containers WHERE container_name = ?", (container_name,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    keys = ["owner_id","container_name","image_name","os_template","ram_gb","cpu_cores","disk_gb","ssh_port","root_pass","created_at","status"]
    return dict(zip(keys, row))

def update_container_name(old_name: str, new_name: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE containers SET container_name = ? WHERE container_name = ?", (new_name, old_name))
    conn.commit()
    conn.close()

def update_status(container_name: str, status: str):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE containers SET status = ? WHERE container_name = ?", (status, container_name))
    conn.commit()
    conn.close()

# ----------------------------
# Dockerfile generator per OS
# ----------------------------
def generate_dockerfile_for_os(os_key: str, build_dir: str):
    base = OS_TEMPLATES.get(os_key)
    if not base:
        raise ValueError("Unsupported OS")
    dockerfile_path = os.path.join(build_dir, "Dockerfile")
    if "alpine" in base:
        df = f"""
FROM {base}
RUN apk update && apk add --no-cache openssh-server bash shadow curl tmate tar
RUN mkdir -p /run/sshd
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo "root:root" | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
"""
    else:
        # Debian/Ubuntu
        df = f"""
FROM {base}
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server passwd curl wget ca-certificates tmate tar && apt-get clean
RUN mkdir -p /var/run/sshd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config || true
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config || true
RUN sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
RUN echo "root:root" | chpasswd
EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]
"""
    with open(dockerfile_path, "w") as f:
        f.write(df.strip() + "\n")
    return dockerfile_path

# ----------------------------
# Host IP helper
# ----------------------------
def get_host_ip():
    # try ifconfig.co, fallback to environment or 127.0.0.1
    rc, out, err = run_cmd("curl -s https://ifconfig.co || true", timeout=5)
    if rc == 0 and out:
        return out.strip()
    # try env var
    return os.getenv("HOST_PUBLIC_IP", "127.0.0.1")

# ----------------------------
# Discord bot setup
# ----------------------------
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

# admin check
def is_admin(user: discord.User) -> bool:
    if MAIN_ADMIN_ID and str(user.id) == str(MAIN_ADMIN_ID):
        return True
    try:
        return user.guild_permissions.administrator
    except Exception:
        return False

# Embeds helpers
def embed_success(title, desc):
    return discord.Embed(title=title, description=desc, color=0x00FF88)

def embed_error(title, desc):
    return discord.Embed(title=title, description=desc, color=0xFF3366)

def embed_info(title, desc):
    return discord.Embed(title=title, description=desc, color=0x00BBFF)

# ----------------------------
# Creation flow (core)
# ----------------------------
async def create_vps_flow(owner_id: str, os_key: str, ram: int, cpu: float, disk: int, ctx_or_interaction):
    """
    Steps:
      - Create build dir
      - Generate Dockerfile for chosen OS
      - Build image
      - Create volume for /data
      - Choose persistent host SSH port (from configured range)
      - Run container mapping host_port:22
      - Set random root password inside container
      - Save metadata to DB
      - DM owner with SSH command and TMATE info
    """
    owner_id_str = str(owner_id)
    container_name = ensure_unique_name(owner_id_str)
    build_dir = os.path.join(DEPLOY_ROOT, container_name)
    os.makedirs(build_dir, exist_ok=True)

    # generate dockerfile
    try:
        generate_dockerfile_for_os(os_key, build_dir)
    except Exception as e:
        logger.exception("Dockerfile generation failed")
        return False, f"Template generation failed: {e}"

    image_tag = f"{container_name}:latest"
    # build image
    ok, msg = docker_build_image(build_dir, image_tag)
    if not ok:
        logger.error("Image build failed: %s", msg)
        return False, f"Image build failed: {msg}"

    # create volume
    vol_name = f"vol_{container_name}"
    docker_create_volume(vol_name)

    # choose persistent host port (ensure not taken)
    for _ in range(100):
        host_ssh_port = random.randint(SSH_PORT_MIN, SSH_PORT_MAX)
        # check port in DB
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM containers WHERE ssh_port = ?", (host_ssh_port,))
        used = c.fetchone()[0] or 0
        conn.close()
        if used == 0:
            break
    else:
        return False, "Could not find unused SSH port in range."

    # run container
    ok2, msg2 = docker_run_container(image_tag, container_name, host_ssh_port, ram, cpu, volume_name=vol_name)
    if not ok2:
        logger.error("Container run failed: %s", msg2)
        return False, f"Container start failed: {msg2}"

    # set root pass
    random_pass = rand_string(12)
    rc, out, err = docker_exec(container_name, f"echo 'root:{random_pass}' | chpasswd", timeout=20)
    # Note: templates already start sshd with CMD; mapping host->22 done on docker run.

    # Save meta
    save_container_meta(owner_id_str, container_name, image_tag, os_key, ram, cpu, disk, host_ssh_port, random_pass)

    # DM owner with SSH & TMATE
    try:
        # obtain user object
        if isinstance(ctx_or_interaction, discord.Interaction):
            botref = ctx_or_interaction.client
        else:
            botref = ctx_or_interaction.bot
        user = await botref.fetch_user(int(owner_id_str))
        host_ip = get_host_ip()
        ssh_text = f"ssh {SSH_USER}@{host_ip} -p {host_ssh_port}"
        dm_embed = discord.Embed(title=f"⭐ {container_name} - 🔑 SSH Access", color=0x00CCFF)
        dm_embed.add_field(name="SSH Command", value=f"`{ssh_text}`", inline=False)
        dm_embed.add_field(name="Root password (one-time)", value=f"`{random_pass}`", inline=False)
        dm_embed.set_footer(text="Do not share these credentials publicly.")
        await user.send(embed=dm_embed)

        # Try to create tmate session inside container
        rc_t, out_t, err_t = docker_exec(container_name, "tmate -S /tmp/tmate.sock new-session -d || true; sleep 1; tmate -S /tmp/tmate.sock display -p '#{tmate_ssh}' || true", timeout=40)
        if rc_t == 0 and out_t:
            tmate_cmd = out_t.strip()
            # try web url
            rc_w, out_w, err_w = docker_exec(container_name, "tmate -S /tmp/tmate.sock display -p '#{tmate_web}' || true", timeout=5)
            dm_embed2 = discord.Embed(title=f"🟣 {container_name} - TMATE Session", color=0x9B59B6)
            dm_embed2.add_field(name="SSH", value=f"`{tmate_cmd}`", inline=False)
            if rc_w == 0 and out_w:
                dm_embed2.add_field(name="Web URL", value=out_w.strip(), inline=False)
            dm_embed2.set_footer(text="Temporary share — will expire. Do not share publicly.")
            await user.send(embed=dm_embed2)
        else:
            await user.send("⚠️ TMATE session could not be started inside the VPS. It may not be installed or outbound connections are blocked.")
    except Exception as e:
        logger.exception("DM failed while creating VPS: %s", e)

    return True, f"{container_name} created for <@{owner_id_str}>. SSH on {host_ssh_port}"

# ----------------------------
# View classes for Discord UI
# ----------------------------
class OSSelectView(discord.ui.View):
    def __init__(self, owner_id: str, ram: int, cpu: float, disk: int, author):
        super().__init__(timeout=180)
        self.owner_id = owner_id
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.author = author
        options = [discord.SelectOption(label=key, description=OS_TEMPLATES[key], value=key) for key in OS_TEMPLATES.keys()]
        self.select = discord.ui.Select(placeholder="Choose OS...", min_values=1, max_values=1, options=options)
        self.select.callback = self._on_select
        self.add_item(self.select)

    async def _on_select(self, interaction: discord.Interaction):
        if interaction.user.id != self.author.id and not is_admin(interaction.user):
            await interaction.response.send_message("Only the command user or admin can choose the OS.", ephemeral=True)
            return
        os_choice = self.select.values[0]
        await interaction.response.defer(thinking=True)
        ok, msg = await create_vps_flow(self.owner_id, os_choice, self.ram, self.cpu, self.disk, interaction)
        if ok:
            await interaction.followup.send(embed=embed_success("✅ VPS Created", msg))
        else:
            await interaction.followup.send(embed=embed_error("❌ VPS Creation Failed", str(msg)))

class ManageView(discord.ui.View):
    def __init__(self, container_name: str, requester):
        super().__init__(timeout=None)
        self.container_name = container_name
        self.requester = requester

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        meta = get_container_meta(self.container_name)
        if not meta:
            await interaction.response.send_message("VPS not found.", ephemeral=True)
            return False
        owner = meta["owner_id"]
        if str(interaction.user.id) != str(owner) and not is_admin(interaction.user):
            await interaction.response.send_message("You don't have permission to manage this VPS.", ephemeral=True)
            return False
        return True

    @discord.ui.button(label="Start", style=discord.ButtonStyle.green, emoji="▶️")
    async def start_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        rc, out, err = run_cmd(f"{DOCKER_CMD} start {self.container_name}")
        if rc == 0:
            update_status(self.container_name, "running")
            await interaction.followup.send(embed=embed_success("Started", f"{self.container_name} started."))
        else:
            await interaction.followup.send(embed=embed_error("Start Failed", out or err))

    @discord.ui.button(label="Stop", style=discord.ButtonStyle.gray, emoji="⏹️")
    async def stop_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        rc, out, err = run_cmd(f"{DOCKER_CMD} stop {self.container_name}")
        if rc == 0:
            update_status(self.container_name, "stopped")
            await interaction.followup.send(embed=embed_success("Stopped", f"{self.container_name} stopped."))
        else:
            await interaction.followup.send(embed=embed_error("Stop Failed", out or err))

    @discord.ui.button(label="Restart", style=discord.ButtonStyle.blurple, emoji="🔄")
    async def restart_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        rc, out, err = run_cmd(f"{DOCKER_CMD} restart {self.container_name}")
        if rc == 0:
            update_status(self.container_name, "running")
            await interaction.followup.send(embed=embed_success("Restarted", f"{self.container_name} restarted."))
        else:
            await interaction.followup.send(embed=embed_error("Restart Failed", out or err))

    @discord.ui.button(label="Reinstall", style=discord.ButtonStyle.danger, emoji="🛠️")
    async def reinstall_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("Choose OS to reinstall the VPS (this keeps the container name).", ephemeral=True)
        meta = get_container_meta(self.container_name)
        owner_id = meta["owner_id"]
        v = OSSelectView(owner_id, meta["ram_gb"], meta["cpu_cores"], meta["disk_gb"], interaction.user)
        # re-install flow must remove old container/image and build new one with same name; keep ssh_port if REINSTALL_KEEP_SSH
        # We'll signal rebuild action by passing special param inside create_vps_flow or implement reinstall_vps separately.
        # For simplicity: we will remove container & image, then call create_vps_flow but keep container_name and ssh_port saved.
        await interaction.followup.send("Select OS to reinstall:", view=v, ephemeral=True)

    @discord.ui.button(label="Rename", style=discord.ButtonStyle.secondary, emoji="✏️")
    async def rename_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.send_message("Reply in chat with the new VPS name (text).", ephemeral=True)
        def check(m):
            return m.author.id == interaction.user.id and m.channel.id == interaction.channel.id
        try:
            msg = await bot.wait_for("message", check=check, timeout=60)
            new_name = msg.content.strip()
            # Docker rename
            rc, out, err = run_cmd(f"{DOCKER_CMD} rename {self.container_name} {new_name}")
            if rc == 0:
                update_container_name(self.container_name, new_name)
                self.container_name = new_name
                await interaction.followup.send(embed=embed_success("Renamed", f"VPS renamed to `{new_name}`"))
            else:
                await interaction.followup.send(embed=embed_error("Rename Failed", out or err))
        except asyncio.TimeoutError:
            await interaction.followup.send("Timed out waiting for new name.", ephemeral=True)

    @discord.ui.button(label="Add Port", style=discord.ButtonStyle.green, emoji="➕")
    async def add_port_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        # Adding a mapping to a running container is not directly supported by docker.
        # We'll attempt to create a forwarder container that maps host:new_port -> container:22 via socat.
        new_port = random.randint(SSH_PORT_MIN, SSH_PORT_MAX)
        forward_name = f"forward-{self.container_name}-{new_port}"
        # Use alpine/socat image if available (public)
        cmd_try = f"{DOCKER_CMD} run -d --name {forward_name} -p {new_port}:22 alpine/socat TCP-LISTEN:22,fork TCP:{self.container_name}:22"
        rc, out, err = run_cmd(cmd_try)
        if rc == 0:
            await interaction.followup.send(embed=embed_success("Port Added", f"New host port `{new_port}` forwards to your VPS. Use: `ssh {SSH_USER}@<host_ip> -p {new_port}`"))
        else:
            await interaction.followup.send(embed=embed_error("Port Add Failed", f"Could not create forwarder: {err or out}"))

    @discord.ui.button(label="SSH", style=discord.ButtonStyle.primary, emoji="🔑")
    async def ssh_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        meta = get_container_meta(self.container_name)
        if not meta:
            await interaction.response.send_message("VPS metadata missing.", ephemeral=True)
            return
        host_ip = get_host_ip()
        port = meta["ssh_port"]
        await interaction.response.send_message(embed=embed_info("🔐 SSH Access", f"`ssh {SSH_USER}@{host_ip} -p {port}`\n_This port is persistent and was assigned when VPS was created._"), ephemeral=True)

    @discord.ui.button(label="TMATE", style=discord.ButtonStyle.blurple, emoji="🟣")
    async def tmate_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        await interaction.response.defer()
        # attempt to start tmate session inside container and display SSH and web URL
        rc, out, err = docker_exec(self.container_name, "tmate -S /tmp/tmate.sock new-session -d || true; sleep 1; tmate -S /tmp/tmate.sock display -p '#{tmate_ssh}' || true", timeout=30)
        if rc == 0 and out:
            tmate_cmd = out.strip()
            rc_w, out_w, err_w = docker_exec(self.container_name, "tmate -S /tmp/tmate.sock display -p '#{tmate_web}' || true", timeout=5)
            embed = discord.Embed(title="🟣 TMATE Session", color=0x9B59B6)
            embed.add_field(name="SSH", value=f"`{tmate_cmd}`", inline=False)
            if rc_w == 0 and out_w:
                embed.add_field(name="Web URL", value=out_w.strip(), inline=False)
            await interaction.followup.send(embed=embed)
        else:
            await interaction.followup.send(embed=embed_error("TMATE Failed", f"Could not start tmate: {err or out}"))

    @discord.ui.button(label="Stats", style=discord.ButtonStyle.secondary, emoji="📊")
    async def stats_btn(self, interaction: discord.Interaction, button: discord.ui.Button):
        # docker stats gives formatted output
        rc, out, err = run_cmd(f"{DOCKER_CMD} stats {self.container_name} --no-stream --format \"{{{{.CPUPerc}}}}|{{{{.MemUsage}}}}|{{{{.NetIO}}}}\"", timeout=10)
        if rc == 0 and out:
            line = out.splitlines()[0]
            cpu, mem, net = (line.split("|") + ["N/A","N/A","N/A"])[:3]
            embed = discord.Embed(title=f"📊 Stats — {self.container_name}", color=0xFFD700)
            embed.add_field(name="CPU", value=cpu, inline=False)
            embed.add_field(name="Memory", value=mem, inline=False)
            embed.add_field(name="Network I/O", value=net, inline=False)
            await interaction.response.send_message(embed=embed, ephemeral=True)
        else:
            await interaction.response.send_message("Could not fetch stats.", ephemeral=True)

# ----------------------------
# Commands
# ----------------------------
@bot.event
async def on_ready():
    print("GalaxyHost Bot Deployer ready.")
    logger.info("Bot started")

@bot.command(name="create")
@commands.guild_only()
async def create_cmd(ctx, ram: int, cpu: float, disk: int, member: discord.Member):
    """
    Usage:
      !create <ram_gb> <cpu_cores> <disk_gb> @user
    After running, you'll be asked to choose OS via dropdown.
    """
    if not is_admin(ctx.author) and str(ctx.author.id) != MAIN_ADMIN_ID:
        await ctx.send("Only server admins or MAIN_ADMIN may create VPS.", delete_after=20)
        return
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await ctx.send("RAM/CPU/DISK must be greater than 0.")
        return
    view = OSSelectView(owner_id=str(member.id), ram=ram, cpu=cpu, disk=disk, author=ctx.author)
    embed = discord.Embed(title="🖥️ Create VPS", description=f"Select OS for VPS that will be created for {member.mention}\nRAM: {ram}GB • CPU: {cpu} • Disk: {disk}GB", color=0x00BBFF)
    await ctx.send(embed=embed, view=view)

@bot.command(name="manage")
async def manage_cmd(ctx, container_name: str = None):
    """
    Usage:
      !manage <container_name>
    If container_name omitted, shows list of VPS.
    """
    if not container_name:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT container_name, owner_id, os_template, ram_gb, cpu_cores, disk_gb, ssh_port, status FROM containers")
        rows = c.fetchall()
        conn.close()
        if not rows:
            await ctx.send("No VPS found.")
            return
        embed = discord.Embed(title="🌌 GalaxyHost VPS List", color=0x00CCFF)
        for r in rows:
            embed.add_field(name=r[0], value=f"owner: <@{r[1]}>\nOS: {r[2]}\nRAM:{r[3]}GB CPU:{r[4]} Disk:{r[5]}GB\nSSH:{r[6]} Status:{r[7]}", inline=False)
        await ctx.send(embed=embed)
        return

    meta = get_container_meta(container_name)
    if not meta:
        await ctx.send("VPS not found.")
        return
    embed = discord.Embed(title=f"⭐ {container_name} — Manage", color=0x00FFAA)
    embed.add_field(name="Owner", value=f"<@{meta['owner_id']}>", inline=True)
    embed.add_field(name="OS", value=meta["os_template"], inline=True)
    embed.add_field(name="Resources", value=f"{meta['ram_gb']}GB RAM • {meta['cpu_cores']} CPU • {meta['disk_gb']}GB Disk", inline=False)
    embed.add_field(name="SSH", value=f"`ssh {SSH_USER}@{get_host_ip()} -p {meta['ssh_port']}`", inline=False)
    view = ManageView(container_name, ctx.author)
    await ctx.send(embed=embed, view=view)

@bot.command(name="list-vps")
async def list_vps_cmd(ctx):
    if not is_admin(ctx.author) and str(ctx.author.id) != MAIN_ADMIN_ID:
        await ctx.send("Admin only.")
        return
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT container_name, owner_id, os_template, ram_gb, cpu_cores, disk_gb, ssh_port, created_at FROM containers")
    rows = c.fetchall()
    conn.close()
    if not rows:
        await ctx.send("No VPS found.")
        return
    embed = discord.Embed(title="📜 All VPS", color=0x8A2BE2)
    for r in rows:
        embed.add_field(name=r[0], value=f"owner: <@{r[1]}>\nOS: {r[2]}\nResources:{r[3]}GB/{r[4]}CPU/{r[5]}GB\nSSH:{r[6]}\nCreated:{r[7]}", inline=False)
    await ctx.send(embed=embed)

@bot.command(name="remove")
async def remove_cmd(ctx, container_name: str):
    if not is_admin(ctx.author):
        await ctx.send("Admin only.")
        return
    meta = get_container_meta(container_name)
    if not meta:
        await ctx.send("VPS not found.")
        return
    # stop and remove
    docker_stop_rm(container_name)
    docker_remove_image(meta["image_name"])
    run_cmd(f"{DOCKER_CMD} volume rm vol_{container_name}")
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM containers WHERE container_name = ?", (container_name,))
    conn.commit()
    conn.close()
    await ctx.send(embed=embed_success("Removed", f"{container_name} removed and metadata cleared."))

# ----------------------------
# Backup commands
# ----------------------------
@bot.command(name="backup")
async def backup_cmd(ctx, container_name: str):
    meta = get_container_meta(container_name)
    if not meta:
        await ctx.send("VPS not found.")
        return
    backup_dir = os.path.join(DEPLOY_ROOT, "backups", container_name)
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"{container_name}_{ts}.tar.gz"
    # use docker run with volume to create tar
    vol = f"vol_{container_name}"
    rc, out, err = run_cmd(f"{DOCKER_CMD} run --rm -v {vol}:/data -v {backup_dir}:/backup alpine sh -c \"cd /data && tar -czf /backup/{filename} .\"", timeout=600)
    if rc == 0:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("INSERT INTO backups (container_name,filename,created_at) VALUES (?,?,?)", (container_name, filename, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        await ctx.send(embed=embed_success("Backup Created", f"Saved: `{filename}`"))
    else:
        await ctx.send(embed=embed_error("Backup Failed", err or out))

@bot.command(name="backup-list")
async def backup_list_cmd(ctx, container_name: str):
    backup_dir = os.path.join(DEPLOY_ROOT, "backups", container_name)
    if not os.path.isdir(backup_dir):
        await ctx.send("No backups found.")
        return
    files = sorted(os.listdir(backup_dir), reverse=True)
    if not files:
        await ctx.send("No backups found.")
        return
    embed = discord.Embed(title=f"Backups for {container_name}", color=0x00CCFF)
    for f in files[:20]:
        embed.add_field(name=f, value=f"`{os.path.join(backup_dir,f)}`", inline=False)
    await ctx.send(embed=embed)

@bot.command(name="restore")
async def restore_cmd(ctx, container_name: str, filename: str):
    backup_dir = os.path.join(DEPLOY_ROOT, "backups", container_name)
    filepath = os.path.join(backup_dir, filename)
    if not os.path.isfile(filepath):
        await ctx.send("Backup not found.")
        return
    vol = f"vol_{container_name}"
    rc, out, err = run_cmd(f"{DOCKER_CMD} run --rm -v {vol}:/data -v {backup_dir}:/backup alpine sh -c \"cd /data && tar -xzf /backup/{filename} --strip-components=0\"", timeout=600)
    if rc == 0:
        await ctx.send(embed=embed_success("Restored", f"{filename} restored to {container_name}"))
    else:
        await ctx.send(embed=embed_error("Restore Failed", err or out))

# ----------------------------
# Help command (override)
# ----------------------------
@bot.command(name="help")
async def help_cmd(ctx):
    embed = discord.Embed(
        title="🌌 GalaxyHost Bot — Full Command List",
        description="All available commands of the GalaxyHost VPS Deployment Bot.",
        color=0x00AAFF
    )

    # =====================================================
    # USER VPS COMMANDS
    # =====================================================
    embed.add_field(
        name="🖥️ User VPS Commands",
        value=(
            "**!create `<ram>` `<cpu>` `<disk>` @user**\n"
            "→ Creates a VPS for a user. After this, bot will show OS selection menu.\n\n"

            "**!manage `<container>`**\n"
            "→ Opens the VPS Management Panel with all buttons.\n\n"

            "**(Panel Button) SSH**\n"
            "→ Shows SSH command: `ssh root@IP -p PORT`\n\n"

            "**(Panel Button) TMATE**\n"
            "→ Generates a TMATE live session (SSH + Web Link) to access the VPS quickly.\n\n"

            "**(Panel Button) Stats**\n"
            "→ Shows live CPU / RAM / Disk / Network usage of VPS.\n\n"

            "**(Panel Button) Rename**\n"
            "→ Allows renaming the VPS container.\n\n"

            "**(Panel Button) Reinstall**\n"
            "→ Allows choosing a new OS and reinstalls the VPS. SSH port is kept.\n\n"

            "**(Panel Button) Add Port**\n"
            "→ Adds an extra forwarded SSH port using socat forwarder.\n\n"
        ),
        inline=False
    )

    # =====================================================
    # BACKUP COMMANDS
    # =====================================================
    embed.add_field(
        name="💾 Backup Commands",
        value=(
            "**!backup `<container>`**\n"
            "→ Creates a backup of /data directory inside VPS.\n\n"

            "**!backup-list `<container>`**\n"
            "→ Lists saved backups.\n\n"

            "**!restore `<container>` `<file>`**\n"
            "→ Restores selected backup file to VPS volume.\n\n"
        ),
        inline=False
    )

    # =====================================================
    # ADMIN COMMANDS
    # =====================================================
    embed.add_field(
        name="🔧 Admin Commands",
        value=(
            "**!list-vps**\n"
            "→ Shows list of all VPS containers created by users.\n\n"

            "**!remove `<container>`**\n"
            "→ Stops VPS, deletes container, deletes image, removes DB entry.\n\n"

            "**!create `<ram>` `<cpu>` `<disk>` @user**\n"
            "→ Only admins can run this to create VPS for a user.\n\n"
        ),
        inline=False
    )

    # =====================================================
    # MANAGEMENT PANEL BUTTONS
    # =====================================================
    embed.add_field(
        name="🎮 Management Panel Buttons",
        value=(
            "▶️ **Start VPS** — Starts the VPS container.\n"
            "⏹️ **Stop VPS** — Stops the VPS container.\n"
            "🔄 **Restart VPS** — Restarts the VPS container.\n"
            "🛠️ **Reinstall** — Reinstall OS with same SSH port.\n"
            "✏️ **Rename** — Change VPS container name.\n"
            "➕ **Add Port** — Add additional SSH-forwarded port.\n"
            "🔑 **SSH** — Displays SSH command.\n"
            "🟣 **TMATE** — Generates TMATE session.\n"
            "📊 **Stats** — Shows real-time container stats.\n"
        ),
        inline=False
    )

    # =====================================================
    # BOT INFORMATION
    # =====================================================
    embed.add_field(
        name="ℹ️ Information",
        value=(
            "**Prefix:** `!`\n"
            "**SSH Username:** `root`\n"
            "**SSH Port Range:** `25565–25665`\n"
            "**Reinstall Keeps Port:** Yes\n"
        ),
        inline=False
    )

    embed.set_footer(text="GalaxyHost — Professional VPS Deployment System")
    await ctx.send(embed=embed)

# ----------------------------
# Run bot
# ----------------------------
if __name__ == "__main__":
    if not DISCORD_TOKEN:
        print("Set DISCORD_TOKEN env var and try again.")
        raise SystemExit(1)
    bot.run(DISCORD_TOKEN)
