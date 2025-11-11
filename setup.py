#!/usr/bin/env python3
"""
Ubuntu 24.04 Server Setup Script (FULLY RESUMABLE)
==================================================
Run as root: sudo python3 setup.py

This script is fully idempotent - it detects completed steps and skips them.
If your setup failed mid-way, just re-run the script.
"""

import subprocess
import sys
import os
import getpass
import shutil
import time

NEW_USER = ""

NPM_COMPOSE = """version: '3.8'
services:
  app:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
"""

def run_cmd(cmd, check=True, capture=False, input_text=None):
    """Execute shell command with error handling"""
    try:
        if not capture:
            print(f"  → {cmd}")
        result = subprocess.run(
            cmd,
            shell=True,
            check=check,
            text=True,
            capture_output=capture,
            input=input_text
        )
        return result
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {e}")
        if check:
            sys.exit(1)
        return e

def check_root():
    if os.geteuid() != 0:
        print("❌ This script must be run as root!")
        sys.exit(1)

def check_ubuntu():
    version = run_cmd("lsb_release -rs", capture=True).stdout.strip()
    if version != "24.04":
        print(f"⚠️  Expected Ubuntu 24.04, found {version}")
        if input("Continue anyway? (yes/no): ").lower() != "yes":
            sys.exit(1)

def get_existing_sudo_users():
    """Get list of existing sudo users"""
    result = run_cmd("getent group sudo | cut -d: -f4", capture=True)
    return result.stdout.strip().split(',') if result.stdout.strip() else []

def prompt_username():
    """Smart username prompt - detects existing users"""
    global NEW_USER
    existing_users = get_existing_sudo_users()
    
    if existing_users and existing_users != ['']:
        print(f"\n📝 Found existing sudo users: {', '.join(existing_users)}")
        use_existing = input("Use existing user for setup? (yes/no): ").lower()
        
        if use_existing == "yes":
            while True:
                user = input("Enter existing username: ").strip().lower()
                if user in existing_users:
                    NEW_USER = user
                    print(f"  → Using existing user: {NEW_USER}")
                    return
                print("❌ User not found or not in sudo group")
    
    # No existing users or user chose to create new
    while True:
        user = input("New sudo username: ").strip().lower()
        if user.isalnum() and len(user) <= 32:
            NEW_USER = user
            break
        print("❌ Use lowercase alphanumeric, max 32 chars")

def user_exists():
    return run_cmd(f"id {NEW_USER}", check=False, capture=True).returncode == 0

def ssh_key_exists():
    auth_file = f"/home/{NEW_USER}/.ssh/authorized_keys"
    return os.path.exists(auth_file) and os.path.getsize(auth_file) > 0

def is_ssh_hardened():
    return run_cmd("grep -q '^PasswordAuthentication no' /etc/ssh/sshd_config", check=False).returncode == 0

def is_fail2ban_active():
    return run_cmd("systemctl is-active fail2ban", check=False, capture=True).returncode == 0

def is_docker_installed():
    return run_cmd("docker --version", check=False, capture=True).returncode == 0

def is_npm_running():
    return run_cmd("docker ps | grep -q nginx-proxy-manager", check=False).returncode == 0

def is_ufw_active():
    return run_cmd("ufw status | grep -q 'Status: active'", check=False).returncode == 0

def get_password():
    while True:
        pwd = getpass.getpass(f"Password for {NEW_USER}: ")
        if len(pwd) < 8:
            print("❌ Password must be at least 8 characters")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if pwd == confirm:
            return pwd
        print("❌ Passwords don't match")

def update_system():
    print("\n📦 Updating System...")
    run_cmd("apt update")
    run_cmd("apt upgrade -y")
    run_cmd("apt autoremove -y")
    print("✅ System updated")

def create_user():
    print(f"\n👤 User Setup: {NEW_USER}")
    
    if user_exists():
        print(f"  → User already exists, skipping creation.")
        # Ensure user is in sudo group
        run_cmd(f"usermod -aG sudo {NEW_USER}", check=False)
    else:
        pwd = get_password()
        run_cmd(f"useradd -m -s /bin/bash {NEW_USER}")
        run_cmd(f"echo '{NEW_USER}:{pwd}' | chpasswd")
        run_cmd(f"usermod -aG sudo {NEW_USER}")
        print(f"✅ User {NEW_USER} created")

def setup_ssh():
    print("\n🔐 SSH Key Setup")
    
    if ssh_key_exists():
        print(f"  → SSH key already exists, skipping.")
        return
    
    ssh_dir = f"/home/{NEW_USER}/.ssh"
    auth_file = f"{ssh_dir}/authorized_keys"
    os.makedirs(ssh_dir, exist_ok=True)
    
    print("Paste your SSH public key (Ctrl+D when done):")
    key_lines = []
    try:
        while True:
            line = input()
            key_lines.append(line)
    except EOFError:
        pass
    
    pub_key = "\n".join(key_lines).strip()
    
    if not pub_key:
        print("❌ No key provided! You WILL be locked out!")
        sys.exit(1)
    
    with open(auth_file, 'w') as f:
        f.write(pub_key + "\n")
    
    run_cmd(f"chmod 700 {ssh_dir}")
    run_cmd(f"chmod 600 {auth_file}")
    run_cmd(f"chown -R {NEW_USER}:{NEW_USER} {ssh_dir}")
    print("✅ SSH key configured")

def verify_ssh_login():
    if is_ssh_hardened():
        print("\n🧪 SSH already hardened, skipping verification.")
        print(f"   Test login with: ssh {NEW_USER}@your-server-ip")
        return
    
    print("\n🧪 VERIFY SSH ACCESS NOW!")
    print(f"Open a NEW terminal and run:")
    print(f"  ssh {NEW_USER}@your-server-ip")
    print("\nIf login succeeds, return here and continue.")
    input("Press Enter when verified...")

def get_ssh_service_name():
    if run_cmd("systemctl list-units --type=service | grep -q '^ssh.service'", check=False).returncode == 0:
        return "ssh"
    return "sshd"

def harden_ssh():
    if is_ssh_hardened():
        print("\n🔒 SSH already hardened, skipping.")
        return
    
    print("\n🔒 Hardening SSH...")
    
    sshd_config = "/etc/ssh/sshd_config"
    backup = f"{sshd_config}.backup.{int(time.time())}"
    shutil.copy2(sshd_config, backup)
    
    with open(sshd_config, 'r') as f:
        lines = f.readlines()
    
    settings = {
        "PermitRootLogin": "no",
        "PasswordAuthentication": "no",
        "PubkeyAuthentication": "yes",
        "ChallengeResponseAuthentication": "no",
        "UsePAM": "yes",
        "X11Forwarding": "no",
        "ClientAliveInterval": "300",
        "ClientAliveCountMax": "2",
        "MaxAuthTries": "3",
        "LoginGraceTime": "30",
        "AllowUsers": NEW_USER
    }
    
    new_config = []
    for line in lines:
        if line.strip() and not line.strip().startswith('#'):
            key = line.split()[0]
            if key in settings:
                new_config.append(f"{key} {settings[key]}\n")
                del settings[key]
                continue
        new_config.append(line)
    
    for k, v in settings.items():
        new_config.append(f"{k} {v}\n")
    
    with open(sshd_config, 'w') as f:
        f.writelines(new_config)
    
    ssh_service = get_ssh_service_name()
    run_cmd("sshd -t")
    run_cmd(f"systemctl restart {ssh_service}")
    print("✅ SSH hardened")

def install_fail2ban():
    if is_fail2ban_active():
        print("\n🛡️  Fail2Ban already active, skipping.")
        return
    
    print("\n🛡️  Installing Fail2Ban...")
    run_cmd("apt install -y fail2ban")
    
    config = f"""[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
"""
    
    with open("/etc/fail2ban/jail.local", 'w') as f:
        f.write(config)
    
    run_cmd("systemctl enable fail2ban")
    run_cmd("systemctl restart fail2ban")
    print("✅ Fail2Ban active")

def install_docker():
    if is_docker_installed():
        print("\n🐳 Docker already installed, skipping.")
        # Ensure user is in docker group
        run_cmd(f"usermod -aG docker {NEW_USER}", check=False)
        return
    
    print("\n🐳 Installing Docker...")
    run_cmd("apt remove -y docker.io docker-doc docker-compose", check=False)
    run_cmd("apt install -y ca-certificates curl gnupg")
    run_cmd("install -m 0755 -d /etc/apt/keyrings")
    run_cmd("curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg")
    run_cmd("chmod a+r /etc/apt/keyrings/docker.gpg")
    
    codename = run_cmd("lsb_release -cs", capture=True).stdout.strip()
    repo = f"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu {codename} stable"
    run_cmd(f'echo "{repo}" > /etc/apt/sources.list.d/docker.list')
    
    run_cmd("apt update")
    run_cmd("apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin")
    
    run_cmd("systemctl enable docker")
    run_cmd("systemctl start docker")
    run_cmd(f"usermod -aG docker {NEW_USER}")
    print("✅ Docker installed")

def install_npm():
    if is_npm_running():
        print("\n🌐 Nginx Proxy Manager already running, skipping.")
        return
    
    print("\n🌐 Installing Nginx Proxy Manager...")
    npm_dir = "/opt/nginx-proxy-manager"
    os.makedirs(npm_dir, exist_ok=True)
    
    with open(f"{npm_dir}/docker-compose.yml", 'w') as f:
        f.write(NPM_COMPOSE)
    
    os.makedirs(f"{npm_dir}/data", exist_ok=True)
    os.makedirs(f"{npm_dir}/letsencrypt", exist_ok=True)
    run_cmd(f"chown -R {NEW_USER}:{NEW_USER} {npm_dir}")
    run_cmd(f"cd {npm_dir} && docker compose up -d")
    
    print("✅ Nginx Proxy Manager running")
    print(f"  📁 Config: {npm_dir}")
    print(f"  🌐 Access: http://your-server-ip:81")
    print(f"  👤 Login: admin@example.com / changeme")
    print("  ⚠️  CHANGE DEFAULT PASSWORD IMMEDIATELY!")

def setup_firewall():
    if is_ufw_active():
        print("\n🔥 UFW firewall already active, skipping.")
        return
    
    print("\n🔥 Setting up Firewall...")
    run_cmd("apt install -y ufw")
    run_cmd("ufw default deny incoming")
    run_cmd("ufw default allow outgoing")
    run_cmd("ufw allow 22/tcp")
    run_cmd("ufw allow 80/tcp")
    run_cmd("ufw allow 81/tcp")
    run_cmd("ufw allow 443/tcp")
    run_cmd("echo 'y' | ufw enable")
    
    print("✅ Firewall active")
    run_cmd("ufw status")

def main():
    print(__doc__)
    check_root()
    check_ubuntu()
    
    if input("\nStart setup? (yes/no): ").lower() != "yes":
        sys.exit(0)
    
    prompt_username()
    
    # Execute setup (each step checks if already done)
    update_system()
    create_user()
    setup_ssh()
    verify_ssh_login()
    harden_ssh()
    install_fail2ban()
    install_docker()
    install_npm()
    setup_firewall()
    
    print("\n" + "="*60)
    print("🎉 SETUP COMPLETE!")
    print("="*60)
    print(f"New sudo user: {NEW_USER}")
    print("\n📋 Next steps:")
    print(f"1. SSH login: ssh {NEW_USER}@your-server-ip")
    print("2. NPM admin: http://your-server-ip:81")
    print("3. Change NPM default credentials!")
    print("4. Keep this root session until SSH is verified")
    print("="*60)

if __name__ == "__main__":
    main()
