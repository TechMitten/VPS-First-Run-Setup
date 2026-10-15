#!/usr/bin/env python3
"""
vps_setup.py - interactive first-run setup for a fresh Debian/Ubuntu VPS.

Released under the MIT License - github.com/techmitten

Run as root on a fresh server. It starts with `apt update && apt upgrade`
(in case you haven't done that yet):

    python3 vps_setup.py

Steps (each one asks before doing anything risky):
  0. Update the system (apt update && apt upgrade)
  1. Install + configure fail2ban for SSH
  2. Enable UFW and allow 22/tcp (checks UFW is installed; asks before installing)
  3. Create a sudo user (asks for name + password)
  4. Optional: SSH key login for that user (with local permission help and a
     live key-login test that waits for your confirmation)
  5. Optional: restrict root login
  6. Optional: disable password logins (main sshd_config AND the drop-in files)
  7. Optional: change the SSH port (UFW + fail2ban updated too)
  8. Optional: install Docker + Docker Compose
  9. Optional: install Nginx Proxy Manager (runs in Docker). If you do, you name a
     Docker network shared with it; apps you install afterwards join that network
     and publish no ports (the proxy reaches them by container name).
 10. Optional: pick apps to install - n8n, Coolify, Dokploy, Open WebUI, Ollama, Gitea,
     Uptime Kuma, Nextcloud, Jellyfin, Tailscale, OpenClaw, Hermes. Each app asks for the
     settings it needs (domains, passwords, API keys) BEFORE installing, and you confirm
     the port it runs on.

Already set up your VPS? Choose "apps only" when the script starts to skip straight to
the app installer (steps 0-9 are skipped).

Safety: sshd config is validated with `sshd -t` before every reload, changes
are rolled back if validation fails, and your current SSH session stays open
the whole time. Keep it open until you've tested a login in a NEW terminal.
"""

import getpass
import ipaddress
import json
import os
import pwd
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    import termios
    import tty
except ImportError:  # not a POSIX terminal; fall back to Enter
    termios = tty = None

TOTAL = 10
TS = datetime.now().strftime("%Y%m%d-%H%M%S")
COLOR = sys.stdout.isatty()

SSHD_MAIN = Path("/etc/ssh/sshd_config")
DROPIN_DIR = Path("/etc/ssh/sshd_config.d")
HARDEN = DROPIN_DIR / "00-hardening.conf"  # sorts first, so it wins
SOCKET_DROPIN = Path("/etc/systemd/system/ssh.socket.d/vps-setup.conf")
FAIL2BAN_JAIL = Path("/etc/fail2ban/jail.d/sshd-local.conf")

STATE = {"ssh_port": 22, "username": None, "key_installed": False,
         "key_verified": False, "ufw": False,
         "net": None}  # Docker network shared with Nginx Proxy Manager (None = no NPM)
SUMMARY = []
_directives = {}  # directives we manage in HARDEN
_backed_up = set()


# --------------------------------------------------------------------------
# Output + prompt helpers
# --------------------------------------------------------------------------
def _c(code, text):
    return f"\033[{code}m{text}\033[0m" if COLOR else text


def info(msg):
    print(_c("36", "[i] ") + msg)


def good(msg):
    print(_c("32", "[ok] ") + msg)


def warn(msg):
    print(_c("33", "[!] ") + msg)


def bad(msg):
    print(_c("31", "[x] ") + msg)


def title(n, text):
    if isinstance(n, str):
        label = n
    else:
        label = "Getting ready" if n == 0 else f"Step {n}/{TOTAL}"
    print("\n" + _c("1;34", f"=== {label}: {text} ===") + "\n")


def press_any_key(prompt="Press any key to begin (Ctrl+C to quit)... "):
    """Wait for a single keypress (falls back to Enter when there is no TTY)."""
    print(prompt, end="", flush=True)
    if termios and sys.stdin.isatty():
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            termios.tcflush(fd, termios.TCIFLUSH)  # drop leftover bytes (arrow keys etc.)
        print()
        if ch == "\x03":
            raise KeyboardInterrupt
    else:
        input()


def splash():
    line = "=" * 62
    print()
    print(_c("1;34", line))
    print(_c("1;34", "   VPS FIRST-RUN SETUP"))
    print()
    print("   MIT License")
    print("   github.com/techmitten")
    print(_c("1;34", line))
    press_any_key()


def ask_yes_no(question, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"{question} {suffix} ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please answer y or n.")


def ask_choice(question, options, default=1):
    print(question)
    for i, label in enumerate(options, 1):
        print(f"  {i}) {label}")
    while True:
        answer = input(f"Choose 1-{len(options)} [{default}]: ").strip()
        if not answer:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer)
        print("  Invalid choice.")


# --------------------------------------------------------------------------
# Command helper
# --------------------------------------------------------------------------
class CmdError(Exception):
    pass


def run(cmd, input_text=None, check=True):
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    proc = subprocess.run(
        cmd, input=input_text, text=True, capture_output=True, env=env
    )
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-800:]
        raise CmdError(f"Command failed: {' '.join(cmd)}\n{detail}")
    return proc


def run_live(cmd, env_extra=None, cwd=None):
    """Like run(), but shows the command's output as it happens (for long jobs
    and interactive wizards, which inherit your terminal)."""
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(cmd, env=env, cwd=cwd)
    if proc.returncode != 0:
        raise CmdError(f"Command failed: {' '.join(cmd)}")


# Wait for other apt/dpkg jobs (fresh VPSes often run unattended-upgrades at
# boot) and keep existing config files instead of prompting.
APT = ["apt-get", "-o", "DPkg::Lock::Timeout=120",
       "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"]


def apt_update():
    run(APT + ["update"])


def apt_install(*packages):
    run(APT + ["install", "-y", *packages])


# --- UFW helpers: every UFW change is a no-op unless UFW is installed ---
def ufw_ready(context):
    """True when UFW is installed. If it isn't, ask before installing it."""
    if shutil.which("ufw"):
        STATE["ufw"] = True
        return True
    warn(f"UFW (the firewall) is not installed, and {context} needs it.")
    if not ask_yes_no("Install UFW now?", True):
        warn("Skipping UFW. No firewall rules will be added.")
        return False
    info("Installing UFW...")
    apt_install("ufw")
    STATE["ufw"] = True
    return True


def ufw_allow(port):
    if STATE["ufw"]:
        run(["ufw", "allow", f"{port}/tcp", "comment", "SSH"])


def ufw_delete(port):
    if STATE["ufw"]:
        run(["ufw", "delete", "allow", f"{port}/tcp"], check=False)


def ufw_reload():
    if STATE["ufw"]:
        run(["ufw", "reload"], check=False)


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------
def detect_client_ip():
    for var in ("SSH_CONNECTION", "SSH_CLIENT"):
        value = os.environ.get(var)
        if value:
            try:
                return str(ipaddress.ip_address(value.split()[0]))
            except ValueError:
                pass
    return None


def server_ip():
    parts = os.environ.get("SSH_CONNECTION", "").split()
    if len(parts) >= 3:
        return parts[2]
    out = run(["hostname", "-I"], check=False).stdout.split()
    return out[0] if out else "YOUR_SERVER_IP"


def port_in_use(port):
    out = run(["ss", "-H", "-tln"]).stdout
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(":", 1)[-1] == str(port):
            return True
    return False


def wait_listening(port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        if port_in_use(port):
            return True
        time.sleep(1)
    return False


CLIENT_IP = detect_client_ip()


# --------------------------------------------------------------------------
# sshd config handling
# --------------------------------------------------------------------------
def sshd_files():
    return [SSHD_MAIN] + sorted(DROPIN_DIR.glob("*.conf"))


def snapshot():
    snap = {p: p.read_text() for p in sshd_files() if p.exists()}
    snap[HARDEN] = HARDEN.read_text() if HARDEN.exists() else None
    return snap


def restore(snap):
    for path, content in snap.items():
        if content is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(content)


def backup_once():
    for path in sshd_files():
        if path == HARDEN or path in _backed_up or not path.exists():
            continue
        dest = path.with_name(path.name + f".bak-{TS}")
        shutil.copy2(path, dest)
        _backed_up.add(path)


def ensure_include():
    text = SSHD_MAIN.read_text()
    if re.search(r"^[ \t]*Include[ \t]+/etc/ssh/sshd_config\.d/", text, re.M):
        return
    SSHD_MAIN.write_text("Include /etc/ssh/sshd_config.d/*.conf\n" + text)


def edit_existing(key, value):
    """Rewrite active `key ...` lines in the main sshd_config and every drop-in
    (except ours). Port lines are commented out instead (Port is additive)."""
    pattern = re.compile(rf"^([ \t]*){re.escape(key)}[ \t]+.*$", re.I | re.M)
    changed = []
    for path in sshd_files():
        if path == HARDEN:
            continue
        text = path.read_text()
        if key.lower() == "port":
            new = pattern.sub(
                lambda m: f"{m.group(1)}# (disabled by vps_setup) {m.group(0).strip()}",
                text,
            )
        else:
            new = pattern.sub(lambda m: f"{m.group(1)}{key} {value}", text)
        if new != text:
            path.write_text(new)
            changed.append(path)
    return changed


def write_harden():
    DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["# Managed by vps_setup.py - this file is read first, so it wins."]
    lines += [f"{k} {v}" for k, v in _directives.items()]
    HARDEN.write_text("\n".join(lines) + "\n")
    HARDEN.chmod(0o644)


def effective():
    out = run(["sshd", "-T"]).stdout
    result = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            result.setdefault(parts[0].lower(), []).append(parts[1].strip().lower())
    return result


def verify_effective(changes):
    eff = effective()
    for key, value in changes.items():
        got = eff.get(key.lower(), [])
        want = str(value).lower()
        if key.lower() == "port":
            ok = set(got) == {want}
        elif key.lower() == "permitrootlogin" and want == "prohibit-password":
            ok = bool(got) and got[0] in ("prohibit-password", "without-password")
        else:
            ok = bool(got) and got[0] == want
        if not ok:
            raise CmdError(
                f"sshd would not use '{key} {value}' (it reports {got or 'nothing'}). "
                "Another config file is overriding it."
            )


def apply_ssh(changes):
    """Apply directives, validate, verify. Rolls back on any failure.
    Returns the list of pre-existing files that were modified."""
    saved_directives = dict(_directives)
    snap = snapshot()
    changed_files = []
    try:
        DROPIN_DIR.mkdir(parents=True, exist_ok=True)
        backup_once()
        ensure_include()
        for key, value in changes.items():
            changed_files += edit_existing(key, value)
            _directives[key] = str(value)
        write_harden()
        os.makedirs("/run/sshd", exist_ok=True)
        run(["sshd", "-t"])
        verify_effective(changes)
    except Exception:
        restore(snap)
        _directives.clear()
        _directives.update(saved_directives)
        raise
    return sorted(set(changed_files))


def ssh_service():
    for name in ("ssh", "sshd"):
        if run(["systemctl", "cat", f"{name}.service"], check=False).returncode == 0:
            return name
    raise CmdError("Could not find the SSH service (ssh.service / sshd.service).")


def reload_ssh(restart=False):
    name = ssh_service()
    action = "restart" if restart else "reload"
    if run(["systemctl", action, name], check=False).returncode != 0:
        run(["systemctl", "restart", name])


def socket_active():
    return run(["systemctl", "is-active", "--quiet", "ssh.socket"], check=False).returncode == 0


def set_socket_port(port):
    """Ubuntu 24.04 starts sshd through ssh.socket, which ignores `Port` in
    sshd_config. Override the socket too. Pass None to remove the override."""
    if not socket_active() and not SOCKET_DROPIN.exists():
        return
    if port is None:
        SOCKET_DROPIN.unlink(missing_ok=True)
    else:
        SOCKET_DROPIN.parent.mkdir(parents=True, exist_ok=True)
        SOCKET_DROPIN.write_text(f"[Socket]\nListenStream=\nListenStream={port}\n")
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "restart", "ssh.socket"])


def current_ssh_ports():
    try:
        return sorted({int(p) for p in effective().get("port", [])})
    except (CmdError, ValueError):
        return []


# --------------------------------------------------------------------------
# fail2ban
# --------------------------------------------------------------------------
def write_fail2ban(port):
    ignore = "127.0.0.1/8 ::1" + (f" {CLIENT_IP}" if CLIENT_IP else "")
    FAIL2BAN_JAIL.parent.mkdir(parents=True, exist_ok=True)
    FAIL2BAN_JAIL.write_text(
        f"""# Managed by vps_setup.py
[DEFAULT]
ignoreip = {ignore}

[sshd]
enabled  = true
port     = {port}
backend  = systemd
maxretry = 5
findtime = 10m
bantime  = 1h
bantime.increment = true
"""
    )


def restart_fail2ban():
    run(["systemctl", "restart", "fail2ban"])


# --------------------------------------------------------------------------
# Steps
# --------------------------------------------------------------------------
def step_fail2ban():
    title(1, "Install and configure fail2ban (protects SSH)")
    ports = current_ssh_ports()
    if ports:
        STATE["ssh_port"] = ports[0]
    info("Installing fail2ban (this can take a minute)...")
    apt_install("fail2ban", "python3-systemd")
    write_fail2ban(STATE["ssh_port"])
    run(["systemctl", "enable", "--now", "fail2ban"])
    restart_fail2ban()
    time.sleep(2)
    status = run(["fail2ban-client", "status", "sshd"], check=False)
    if status.returncode == 0:
        good("fail2ban is running with the sshd jail enabled.")
    else:
        warn("fail2ban installed, but the sshd jail status check failed. "
             "Check with: fail2ban-client status sshd")
    info("Rule: 5 failed logins in 10 minutes = 1 hour ban (grows for repeat offenders).")
    if CLIENT_IP:
        info(f"Your current IP ({CLIENT_IP}) is whitelisted so you can't ban yourself by accident.")
    SUMMARY.append("fail2ban installed, sshd jail active")


def step_ufw():
    title(2, "Enable the UFW firewall")
    if not ufw_ready("the firewall setup"):
        SUMMARY.append("UFW skipped (not installed, install declined)")
        return
    run(["ufw", "default", "deny", "incoming"])
    run(["ufw", "default", "allow", "outgoing"])
    ufw_allow(22)
    for port in current_ssh_ports():
        if port != 22:
            ufw_allow(port)
            info(f"sshd is also on port {port}; allowed that too so you don't get locked out.")
    run(["ufw", "--force", "enable"])
    good("UFW is enabled: incoming denied by default, 22/tcp allowed.")
    SUMMARY.append("UFW enabled (deny incoming, allow 22/tcp)")


USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def step_user():
    title(3, "Create a sudo user")
    if not shutil.which("sudo"):
        info("Installing sudo...")
        apt_install("sudo")

    while True:
        name = input("Username for the new sudo user: ").strip()
        if name == "root" or not USER_RE.match(name):
            warn("Use lowercase letters, digits, '-' or '_' (start with a letter), not 'root'.")
            continue
        try:
            pwd.getpwnam(name)
            exists = True
        except KeyError:
            exists = False
        if exists:
            warn(f"User '{name}' already exists.")
            if not ask_yes_no("Use it anyway (adds it to sudo and sets a new password)?", False):
                continue
        break

    while True:
        pw1 = getpass.getpass(f"Password for {name} (min 8 chars, hidden): ")
        if len(pw1) < 8:
            warn("Too short - use at least 8 characters.")
            continue
        if pw1 != getpass.getpass("Confirm password: "):
            warn("Passwords don't match, try again.")
            continue
        break

    if not exists:
        run(["useradd", "-m", "-s", "/bin/bash", name])
    run(["chpasswd"], input_text=f"{name}:{pw1}\n")
    run(["usermod", "-aG", "sudo", name])
    groups = run(["id", "-nG", name]).stdout.split()
    if "sudo" not in groups:
        raise CmdError(f"'{name}' is not in the sudo group.")
    STATE["username"] = name
    good(f"User '{name}' is ready and is in the sudo group.")
    SUMMARY.append(f"sudo user '{name}' created")


PUB_RE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|"
    r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) "
    r"[A-Za-z0-9+/=]+( .*)?$"
)


def validate_pubkey(key):
    if "PRIVATE KEY" in key:
        return "That is a PRIVATE key. Never share it! Paste the contents of the .pub file instead."
    if not PUB_RE.match(key):
        return "That doesn't look like a public key (it should start with ssh-ed25519 or ssh-rsa)."
    if shutil.which("ssh-keygen"):
        with tempfile.NamedTemporaryFile("w", suffix=".pub", delete=False) as tmp:
            tmp.write(key + "\n")
            tmp_path = tmp.name
        try:
            if run(["ssh-keygen", "-l", "-f", tmp_path], check=False).returncode != 0:
                return "ssh-keygen rejected that key - it may have been cut off when pasting."
        finally:
            os.unlink(tmp_path)
    return None


LOCAL_PERMS_HELP = r"""
Set the right permissions on YOUR LOCAL computer (SSH refuses keys that
other users can read - you'd see "UNPROTECTED PRIVATE KEY FILE"):

  Linux / macOS (Terminal):
      chmod 700 ~/.ssh
      chmod 600 ~/.ssh/id_ed25519
      chmod 644 ~/.ssh/id_ed25519.pub

  Windows (PowerShell):
      icacls "$env:USERPROFILE\.ssh" /inheritance:r
      icacls "$env:USERPROFILE\.ssh" /grant:r "${env:USERNAME}:(OI)(CI)F"
      icacls "$env:USERPROFILE\.ssh\id_ed25519" /inheritance:r
      icacls "$env:USERPROFILE\.ssh\id_ed25519" /grant:r "${env:USERNAME}:F"

  (If you saved the key under a different name, use that file name instead
   of id_ed25519. The private key = no .pub; never share it.)
"""


def ssh_login_command(user, with_key_only=False):
    port = STATE["ssh_port"]
    cmd = "ssh "
    if with_key_only:
        # Forces key auth so a password fallback can't make the test look like it worked.
        cmd += "-o PreferredAuthentications=publickey "
    if port != 22:
        cmd += f"-p {port} "
    return cmd + f"{user}@{server_ip()}"


def key_login_seen(user):
    """Look in the SSH logs for a recent 'Accepted publickey' for this user."""
    needle = f"Accepted publickey for {user} "
    chunks = []
    try:
        chunks.append(run(["journalctl", "-u", ssh_service(), "--since", "30 minutes ago",
                           "--no-pager"], check=False).stdout)
    except CmdError:
        pass
    auth_log = Path("/var/log/auth.log")
    if auth_log.exists():
        chunks.append(auth_log.read_text(errors="ignore")[-200000:])
    return any(needle in chunk for chunk in chunks)


def show_recent_ssh_log():
    try:
        out = run(["journalctl", "-u", ssh_service(), "-n", "15", "--no-pager"],
                  check=False).stdout.strip()
    except CmdError:
        return
    if out:
        print("\nLast SSH log lines on the server (they usually say why a login failed):\n")
        print(out + "\n")


def test_key_login(user):
    """Make the user log in with the key in a NEW terminal and wait for confirmation."""
    print(_c("1", "\n--- Test your key login now ---"))
    print(LOCAL_PERMS_HELP)
    print(
        "Then, in a NEW terminal on your local computer (keep THIS one open), run:\n\n"
        + _c("1", f"    {ssh_login_command(user, with_key_only=True)}")
        + "\n\nYou should be let in using the key (you may be asked for the KEY'S "
        "passphrase, never for the account password).\n"
        "The first time, SSH asks to trust the server fingerprint: type 'yes'.\n"
    )
    while True:
        answer = input("Type 'ok' once you're logged in with the key, 'help' for "
                       "troubleshooting, or 'skip': ").strip().lower()
        if answer == "skip":
            warn("Key login NOT verified. Don't disable passwords until it works.")
            return False
        if answer == "help":
            print(
                "\nTroubleshooting:\n"
                "  - 'Permission denied (publickey)': the key you're using doesn't match the one "
                "you pasted here, or the local permissions above are wrong.\n"
                "  - Try forcing the key file:  ssh -i ~/.ssh/id_ed25519 ... (Windows: "
                "-i $env:USERPROFILE\\.ssh\\id_ed25519)\n"
                "  - 'Connection timed out': a firewall (UFW or your provider's panel) is blocking "
                f"port {STATE['ssh_port']}.\n"
                "  - Add -v to the ssh command for detailed output."
            )
            show_recent_ssh_log()
            continue
        if answer != "ok":
            continue
        if key_login_seen(user):
            good("Confirmed: the server logged a successful key login for "
                 f"'{user}'.")
            return True
        warn("I can't see a key login for this user in the server logs yet.")
        if ask_yes_no("Is that wrong - did you really get in with the key (not the password)?",
                      False):
            warn("Continuing on your word.")
            return True
        print("Try the login command again (it needs the -o PreferredAuthentications=publickey "
              "part), or type 'help'.")


def step_ssh_key():
    user = STATE["username"]
    title(4, f"SSH key login for '{user}'")
    info(f"Continuing as '{user}': the key files below are created by and owned by that user.")
    if not ask_yes_no(f"Enable SSH key login for '{user}'?", True):
        info("Skipped. (You can still log in with the password.)")
        return

    ip = server_ip()
    print(
        "\nOn YOUR LOCAL computer (not this server), open a terminal / PowerShell and run:\n\n"
        + _c("1", '    ssh-keygen -t ed25519 -C "my-vps"\n')
        + "\nPress Enter to accept the default location and set a passphrase when asked.\n"
        "Then print your PUBLIC key:\n\n"
        + _c("1", "    Linux/macOS:         cat ~/.ssh/id_ed25519.pub\n")
        + _c("1", "    Windows PowerShell:  Get-Content $env:USERPROFILE\\.ssh\\id_ed25519.pub\n")
        + "\nCopy that one line (it starts with 'ssh-ed25519') and paste it below.\n"
        "Only paste the .pub file, never the private key.\n"
    )

    while True:
        key = input("Paste your public key (or type 'skip'): ").strip()
        if key.lower() == "skip":
            info("Skipped key setup.")
            return
        problem = validate_pubkey(key)
        if problem:
            warn(problem)
            continue
        break

    home = Path(pwd.getpwnam(user).pw_dir)
    ssh_dir = home / ".ssh"
    auth = ssh_dir / "authorized_keys"
    as_user = ["runuser", "-u", user, "--"]

    run(as_user + ["mkdir", "-p", str(ssh_dir)])
    run(as_user + ["chmod", "700", str(ssh_dir)])

    existing = auth.read_text() if auth.exists() else ""
    key_id = " ".join(key.split()[:2])
    if key_id in existing:
        info("That key is already in authorized_keys.")
    else:
        payload = ("\n" if existing and not existing.endswith("\n") else "") + key + "\n"
        run(as_user + ["sh", "-c", 'umask 077; cat >> "$1"', "sh", str(auth)],
            input_text=payload)
    run(as_user + ["chmod", "600", str(auth)])
    run(as_user + ["chmod", "go-w", str(home)])  # sshd rejects keys if home is group/world writable

    uid = pwd.getpwnam(user).pw_uid
    if auth.stat().st_uid != uid or ssh_dir.stat().st_uid != uid:
        run(["chown", "-R", f"{user}:{user}", str(ssh_dir)])

    good(f"Saved key to {auth}")
    info(f"Permissions: {ssh_dir} = 700, {auth} = 600, owner = {user}")
    STATE["key_installed"] = True
    SUMMARY.append(f"SSH key installed for '{user}'")

    if test_key_login(user):
        STATE["key_verified"] = True
        SUMMARY.append(f"SSH key login for '{user}' verified")


def step_root_login():
    title(5, "Root login over SSH")
    choice = ask_choice(
        "How should root be allowed to log in over SSH?",
        [
            "Disable root login completely (recommended)",
            "Key only - root may log in with an SSH key, never a password",
            "Leave it as it is",
        ],
        1,
    )
    if choice == 3:
        info("Left unchanged.")
        return
    if choice == 2:
        root_keys = Path("/root/.ssh/authorized_keys")
        if not root_keys.exists() or not root_keys.read_text().strip():
            warn("root has no key in /root/.ssh/authorized_keys, so this would "
                 "effectively lock root out of SSH.")
            if not ask_yes_no("Apply it anyway?", False):
                info("Left unchanged.")
                return
        value = "prohibit-password"
    else:
        value = "no"
    changed = apply_ssh({"PermitRootLogin": value})
    reload_ssh()
    good(f"PermitRootLogin is now '{value}'.")
    if changed:
        info("Also updated: " + ", ".join(str(p) for p in changed))
    warn(f"Make sure you can log in as '{STATE['username']}' before closing this root session.")
    SUMMARY.append(f"PermitRootLogin = {value}")


def step_password_auth():
    user = STATE["username"]
    title(6, "Disable SSH password logins")
    if not STATE["key_installed"]:
        auth = Path(pwd.getpwnam(user).pw_dir) / ".ssh" / "authorized_keys"
        if auth.exists() and auth.read_text().strip():
            STATE["key_installed"] = True
    if not STATE["key_installed"]:
        warn("No SSH key is set up for the new user, so disabling passwords would lock "
             "you out. Skipping this step.")
        return
    if not ask_yes_no("Disable password logins (SSH keys only)?", True):
        info("Left unchanged.")
        return

    if STATE["key_verified"]:
        info("Your key login was already verified in step 4.")
    elif not test_key_login(user):
        warn("Not disabling passwords. Fix the key login first, then re-run this script.")
        return
    else:
        STATE["key_verified"] = True

    changes = {
        "PasswordAuthentication": "no",
        "KbdInteractiveAuthentication": "no",
        "PubkeyAuthentication": "yes",
    }
    try:
        changed = apply_ssh(changes)
    except CmdError:
        # Older OpenSSH doesn't know KbdInteractiveAuthentication.
        changes.pop("KbdInteractiveAuthentication")
        changed = apply_ssh(changes)
    reload_ssh()
    good("Password logins are disabled.")
    info("Updated: " + ", ".join(str(p) for p in ([SSHD_MAIN] if SSHD_MAIN in changed else [])
                                  + [p for p in changed if p != SSHD_MAIN] + [HARDEN]))
    info("sudo still asks for your account password - that's unrelated to SSH.")
    SUMMARY.append("SSH password login disabled")


def revert_port(old, new):
    try:
        apply_ssh({"Port": str(old)})
        set_socket_port(None)
        reload_ssh(restart=True)
        write_fail2ban(old)
        restart_fail2ban()
    finally:
        ufw_delete(new)
        ufw_reload()
        STATE["ssh_port"] = old


def step_port():
    title(7, "Change the SSH port")
    if not ask_yes_no("Change the SSH port?", False):
        info("Left unchanged.")
        return
    old = STATE["ssh_port"]
    while True:
        answer = input("New SSH port (1024-65535): ").strip()
        if not answer.isdigit() or not 1024 <= int(answer) <= 65535:
            warn("Enter a number between 1024 and 65535.")
            continue
        new = int(answer)
        if new == old:
            warn("That's already the current port.")
            continue
        if port_in_use(new):
            warn(f"Port {new} is already in use by another service.")
            continue
        break

    if ufw_ready("opening the new SSH port"):
        info(f"Opening {new}/tcp in the firewall first...")
        ufw_allow(new)
        ufw_reload()
        if "inactive" in run(["ufw", "status"], check=False).stdout.lower():
            info("UFW is installed but not enabled yet, so this rule applies once it is "
                 "(step 2 enables it).")
    else:
        warn(f"No firewall rule added for {new}/tcp. Make sure no other firewall "
             "(like your provider's panel) blocks it.")

    try:
        apply_ssh({"Port": str(new)})
        set_socket_port(new)
        reload_ssh(restart=True)
        if not wait_listening(new):
            raise CmdError(f"sshd is not listening on port {new}.")
    except CmdError as exc:
        bad(str(exc))
        warn("Rolling back to the old port...")
        revert_port(old, new)
        return

    write_fail2ban(new)
    restart_fail2ban()
    STATE["ssh_port"] = new
    good(f"sshd now listens on port {new}; UFW and fail2ban were updated.")

    user = STATE["username"]
    print(
        "\nKeep THIS session open. In a NEW terminal on your local computer, test:\n\n"
        + _c("1", f"    ssh -p {new} {user}@{server_ip()}")
        + "\n\nNote: if your VPS provider has its own firewall (cloud panel), open "
        f"port {new}/tcp there too.\n"
    )
    while True:
        answer = input("Type 'ok' when the new port works, or 'revert' to go back: ").strip().lower()
        if answer == "revert":
            revert_port(old, new)
            good(f"Reverted to port {old}.")
            return
        if answer == "ok":
            break
    if STATE["ufw"]:
        # The new port is confirmed working, so the old one is removed from UFW automatically.
        info(f"Removing the old SSH port {old}/tcp from the firewall...")
        ufw_delete(old)
        ufw_reload()
        status = run(["ufw", "status"], check=False).stdout
        left = [ln.strip() for ln in status.splitlines()
                if re.match(rf"^({old}(/tcp)?|OpenSSH)\s", ln.strip())]
        if left:
            warn(f"UFW still lists a rule that may allow port {old}: " + " | ".join(left)
                 + f"\n    Check it with:  ufw status numbered   (remove with: ufw delete <number>)")
        else:
            good(f"Closed {old}/tcp in the firewall.")
    SUMMARY.append(f"SSH port changed {old} -> {new}")


def os_release():
    data = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            data[key] = value.strip().strip('"')
    return data


def step_docker():
    title(8, "Install Docker and Docker Compose")
    if not ask_yes_no("Install Docker Engine + Docker Compose?", True):
        info("Skipped.")
        return
    install_docker()


def install_docker():
    rel = os_release()
    ids = [rel.get("ID", "")] + rel.get("ID_LIKE", "").split()
    if "ubuntu" in ids:
        distro, codename = "ubuntu", rel.get("UBUNTU_CODENAME") or rel.get("VERSION_CODENAME")
    elif "debian" in ids:
        distro, codename = "debian", rel.get("VERSION_CODENAME")
    else:
        raise CmdError("Only Debian/Ubuntu are supported for the Docker install.")

    info("Adding Docker's official apt repository...")
    apt_install("ca-certificates")
    keyring = Path("/etc/apt/keyrings")
    keyring.mkdir(mode=0o755, parents=True, exist_ok=True)
    key_data = urllib.request.urlopen(
        f"https://download.docker.com/linux/{distro}/gpg", timeout=30
    ).read()
    (keyring / "docker.asc").write_bytes(key_data)
    (keyring / "docker.asc").chmod(0o644)
    Path("/etc/apt/sources.list.d/docker.sources").write_text(
        f"Types: deb\n"
        f"URIs: https://download.docker.com/linux/{distro}\n"
        f"Suites: {codename}\n"
        f"Components: stable\n"
        f"Signed-By: /etc/apt/keyrings/docker.asc\n"
    )
    apt_update()
    info("Installing Docker (this can take a few minutes)...")
    apt_install("docker-ce", "docker-ce-cli", "containerd.io",
                "docker-buildx-plugin", "docker-compose-plugin")
    run(["systemctl", "enable", "--now", "docker"])

    print(run(["docker", "--version"]).stdout.strip())
    print(run(["docker", "compose", "version"]).stdout.strip())
    good("Docker and Docker Compose are installed.")

    user = STATE["username"]
    if ask_yes_no(f"Let '{user}' run docker without sudo? (the docker group is root-equivalent)", True):
        run(["usermod", "-aG", "docker", user])
        info(f"Added '{user}' to the docker group (takes effect at their next login).")
    SUMMARY.append("Docker + Docker Compose installed")


def step_system_update():
    title(0, "Update the system (apt update && apt upgrade)")
    info("Running apt update and apt upgrade in case it hasn't been done yet. "
         "This can take a few minutes...\n")
    run_live(APT + ["update"])
    run_live(APT + ["-y", "upgrade"])
    good("System packages are up to date.")
    SUMMARY.append("apt update && apt upgrade ran")
    if Path("/var/run/reboot-required").exists():
        warn("The upgrade installed something that needs a reboot (usually a new kernel).")
        info("You can keep going and reboot at the end, or reboot now and re-run this script.")
        if ask_yes_no("Reboot now?", False):
            info("Rebooting... reconnect in a minute and run the script again.")
            run(["systemctl", "reboot"], check=False)
            sys.exit(0)


NPM_DIR = Path("/opt/nginx-proxy-manager")


def render_npm_compose(web_bind, admin_bind, net, admin_port=81):
    """Nginx Proxy Manager joins the shared network so apps can be proxied by container name."""
    return (
        "# Generated by vps_setup.py\n"
        "# 'bind' addresses control who can reach each port. Docker bypasses UFW for\n"
        "# published ports, so 127.0.0.1 here is what keeps a port private.\n"
        "# Apps on the shared network are reached by container name (e.g. http://n8n:5678)\n"
        "# and publish no ports of their own.\n"
        "services:\n"
        "  nginx-proxy-manager:\n"
        "    image: jc21/nginx-proxy-manager:latest\n"
        "    container_name: nginx-proxy-manager\n"
        "    restart: unless-stopped\n"
        "    ports:\n"
        f'      - "{web_bind}:80:80"\n'
        f'      - "{web_bind}:443:443"\n'
        f'      - "{admin_bind}:{admin_port}:81"\n'
        "    volumes:\n"
        "      - ./data:/data\n"
        "      - ./letsencrypt:/etc/letsencrypt\n"
        "    networks:\n"
        "      - shared\n"
        "\n"
        "networks:\n"
        "  shared:\n"
        "    external: true\n"
        f"    name: {net}\n"
    )


def step_npm():
    title(9, "Nginx Proxy Manager (optional)")
    if not ask_yes_no("Install Nginx Proxy Manager (web UI for reverse proxies + free SSL "
                      "certificates)?", False):
        info("Skipped.")
        return
    install_npm()


def install_npm():
    if not shutil.which("docker"):
        warn("Nginx Proxy Manager runs in Docker, which isn't installed.")
        if not ask_yes_no("Install Docker now?", True):
            info("Skipped.")
            return
        install_docker()
        if not shutil.which("docker"):
            raise CmdError("Docker still isn't available after the install.")

    compose = NPM_DIR / "docker-compose.yml"
    if compose.exists():
        if not ask_yes_no(f"{compose} already exists. Overwrite it?", False):
            info("Skipped.")
            return
        # Free its own ports before the busy-port check below.
        run(["docker", "compose", "-f", str(compose), "down"], check=False)

    busy = [p for p in (80, 443) if port_in_use(p)]
    if busy:
        warn("These ports are already in use on this server: "
             + ", ".join(str(p) for p in busy)
             + ". Nginx Proxy Manager needs 80 and 443 (Coolify and Dokploy use them too), "
             "so I'm skipping it.")
        return

    print(
        "\nNginx Proxy Manager uses ports 80 and 443 (web traffic) and an admin panel (81 by\n"
        "default). Docker bypasses UFW for published ports, so the address each port is\n"
        "bound to is what decides who can reach it.\n"
    )
    admin_port = ask_port("the Nginx Proxy Manager admin panel", 81, avoid=(80, 443))
    if admin_port is None:
        info("Skipped.")
        return

    public_web = ask_yes_no(
        "Serve web traffic straight from this server on ports 80 and 443?\n"
        "(Say No if a tunnel such as Cloudflare Tunnel sits in front, or you only want "
        "local access.)", False)
    web_bind = "0.0.0.0" if public_web else "127.0.0.1"
    admin_bind = ask_bind("the Nginx Proxy Manager admin panel")

    print(
        "\nApps you install later join a Docker network shared with Nginx Proxy Manager. They "
        "publish no ports at all - the proxy reaches them by container name, so only the proxy "
        "is exposed.\n"
    )
    net = ask_net_name(STATE["net"] or "proxy")

    user = STATE["username"]
    ensure_network(net)
    NPM_DIR.mkdir(parents=True, exist_ok=True)
    compose.write_text(render_npm_compose(web_bind, admin_bind, net, admin_port))
    chown_to(user, NPM_DIR, compose)
    good(f"Wrote {compose}")

    info("Pulling the image and starting it (can take a minute)...")
    run(["docker", "compose", "-f", str(compose), "up", "-d"])
    if not wait_listening(admin_port, timeout=60):
        raise CmdError("Nginx Proxy Manager did not start listening on port "
                       f"{admin_port}. Check: docker compose -f {compose} logs")
    good("Nginx Proxy Manager is running.")
    STATE["net"] = net
    save_state()
    good(f"Docker network '{net}' created. Apps installed from now on use it and publish no ports.")

    port_flag = f"-p {STATE['ssh_port']} " if STATE["ssh_port"] != 22 else ""
    if admin_bind == "127.0.0.1":
        print(
            "\nOpen the admin panel through an SSH tunnel. On YOUR LOCAL computer, run:\n\n"
            + _c("1", f"    ssh -L 8181:127.0.0.1:{admin_port} {port_flag}{user}@{server_ip()}")
            + "\n\nthen browse to  http://localhost:8181  (keep that SSH window open).\n"
        )
    elif admin_bind == "0.0.0.0":
        warn(f"The admin panel is PUBLIC at http://{server_ip()}:{admin_port} - set up its login "
             "right away, then consider restricting it.")
    else:
        print(f"\nAdmin panel: http://{admin_bind}:{admin_port} (reachable only via that IP).\n")
    info("First login: NPM either asks you to create the admin account, or uses the default "
         "admin@example.com / changeme. Change that immediately if you see it.")
    if not public_web:
        info(f"Ports 80/443 are bound to localhost only. To serve the internet directly, edit "
             f"{compose} (change 127.0.0.1 to 0.0.0.0 on the 80 and 443 lines), then run: "
             f"docker compose -f {compose} up -d")
    SUMMARY.append(f"Nginx Proxy Manager installed ({NPM_DIR}); admin on {admin_bind}:{admin_port}; "
                   f"shared network '{net}'")


# --------------------------------------------------------------------------
# Optional apps (Docker apps + a few host installs)
# --------------------------------------------------------------------------
APPS_DIR = Path("/opt/apps")
STATE_FILE = APPS_DIR / ".vps-setup.json"
DEFAULT_APPS_NET = "apps"          # shared by apps that talk to each other (no NPM)
RESERVED_NETS = {"bridge", "host", "none"}

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
NET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,100}$")
URL_RE = re.compile(r"^https?://\S+$")


# --- validators (return an error message, or None when the value is fine) ---
def v_domain(value):
    if DOMAIN_RE.match(value):
        return None
    return "Enter a domain like app.example.com (no http://, no slashes)."


def v_email(value):
    return None if EMAIL_RE.match(value) else "That doesn't look like an email address."


def v_url(value):
    return None if URL_RE.match(value) else "Enter a full URL starting with http:// or https://"


def v_min(length):
    return lambda value: None if len(value) >= length else f"Use at least {length} characters."


def v_user_basic(value):
    if re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,38}$", value):
        return None
    return "Use 2-39 letters, digits, '.', '-' or '_' (start with a letter or digit)."


def v_user_not_reserved(value):
    problem = v_user_basic(value)
    if problem:
        return problem
    if value.lower() in ("admin", "root", "administrator", "api", "user", "gitea"):
        return "That name is reserved by the app - pick another."
    return None


def v_strong(value):
    if len(value) < 10:
        return "Use at least 10 characters."
    if not (re.search("[a-z]", value) and re.search("[A-Z]", value)
            and re.search(r"\d", value) and re.search(r"[^A-Za-z0-9]", value)):
        return "Mix upper and lower case letters, a number and a symbol."
    return None


def v_abs_path(value):
    return None if value.startswith("/") else "Enter an absolute path starting with /"


def v_model(value):
    return None if MODEL_RE.match(value) else "That doesn't look like a model name (e.g. llama3.2:3b)."


# --- generators ---
def gen_secret(nbytes=24):
    return secrets.token_hex(nbytes)


def gen_password(length=20):
    """Strong password that is safe inside .env files and command lines."""
    upper, lower = "ABCDEFGHJKLMNPQRSTUVWXYZ", "abcdefghijkmnopqrstuvwxyz"
    digits, symbols = "23456789", "!@#%^*-_+="
    pool = upper + lower + digits + symbols
    while True:
        pw = "".join(secrets.choice(pool) for _ in range(length))
        if (any(c in upper for c in pw) and any(c in lower for c in pw)
                and any(c in digits for c in pw) and any(c in symbols for c in pw)):
            return pw


def system_tz():
    try:
        tz = Path("/etc/timezone").read_text().strip()
        if tz:
            return tz
    except OSError:
        pass
    link = os.path.realpath("/etc/localtime")
    if "zoneinfo/" in link:
        return link.split("zoneinfo/", 1)[1]
    return "UTC"


def memory_gb():
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) / 1024 / 1024
    except (OSError, ValueError):
        pass
    return 0.0


# --- prompts ---
def ask_value(label, default=None, secret=False, required=False, generate=False,
              gen=None, auto=False, confirm=False, validate=None, hint=None, shown=None):
    """Ask for one setting before anything is installed.

    generate=True  -> pressing Enter creates a strong random value
    auto=True      -> don't ask at all, generate it
    shown=<list>   -> generated values are added to the list so they can be displayed once
    """
    gen = gen or gen_secret
    if generate and auto:
        value = gen()
        if shown is not None:
            shown.append((label, value))
        return value
    if hint:
        print(_c("2", f"  {hint}"))
    if generate:
        suffix = " [Enter = generate a strong random value]"
    elif default not in (None, ""):
        suffix = f" [{default}]"
    elif required:
        suffix = ""
    else:
        suffix = " [Enter = skip]"
    while True:
        prompt = f"{label}{suffix}: "
        value = (getpass.getpass(prompt) if secret else input(prompt)).strip()
        if not value:
            if generate:
                value = gen()
                if shown is not None:
                    shown.append((label, value))
                return value
            if default not in (None, ""):
                return str(default)
            if required:
                warn("This value is required.")
                continue
            return ""
        if "'" in value or "\n" in value:
            warn("Single quotes aren't allowed in this value.")
            continue
        if validate:
            problem = validate(value)
            if problem:
                warn(problem)
                continue
        if secret and confirm and getpass.getpass("Confirm: ").strip() != value:
            warn("Values don't match, try again.")
            continue
        return value


def ask_auto(ctx):
    ctx["auto"] = ask_yes_no(
        "Auto-generate this app's internal passwords and keys? (recommended; say No to type "
        "your own)", True)


def ask_port(label, default, avoid=()):
    """Ask which port an app should use. Enter keeps the default shown."""
    port = default
    while True:
        answer = input(f"Port for {label} [{port}] (Enter to accept, or 'skip'): ").strip().lower()
        if answer == "skip":
            return None
        if answer:
            if not answer.isdigit() or not 1 <= int(answer) <= 65535:
                warn("Enter a port number between 1 and 65535.")
                continue
            port = int(answer)
        if port in avoid:
            warn(f"Port {port} is already used by another part of this app - choose another.")
            continue
        if port_in_use(port):
            warn(f"Port {port} is already in use on this server - choose another.")
            continue
        return port


def tailscale_ip():
    if not shutil.which("tailscale"):
        return None
    out = run(["tailscale", "ip", "-4"], check=False).stdout.split()
    return out[0] if out else None


def ask_bind(label, allow_public=True):
    options = [
        "Only this server (127.0.0.1) - open it through an SSH tunnel (recommended)",
        "A specific IP on this server, e.g. your Tailscale IP",
    ]
    if allow_public:
        options.append("Everyone on the internet (NOT recommended)")
    choice = ask_choice(f"\nWho should be able to reach {label}?", options, 1)
    if choice == 1:
        return "127.0.0.1"
    if choice == 2:
        local_ips = run(["hostname", "-I"], check=False).stdout.split()
        ts = tailscale_ip()
        suffix = f" [{ts}]" if ts else ""
        while True:
            value = input(f"IP address to bind {label} to{suffix}: ").strip() or (ts or "")
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                warn("That isn't a valid IP address.")
                continue
            if ip.version != 4 or value not in local_ips:
                warn("That must be an IPv4 address that exists on this server "
                     f"(found: {', '.join(local_ips) or 'none'}).")
                continue
            return value
    if ask_yes_no(f"{label} would be open to the whole internet. Really do that?", False):
        return "0.0.0.0"
    info("Keeping it on 127.0.0.1.")
    return "127.0.0.1"


# --- shared Docker network (Nginx Proxy Manager <-> apps) ---
def ask_net_name(default="proxy"):
    while True:
        name = input(f"Name for the shared Docker network [{default}]: ").strip() or default
        if name in RESERVED_NETS or not NET_RE.match(name):
            warn("Use letters, digits, '.', '-' or '_' (and not bridge/host/none).")
            continue
        return name


def ensure_network(name):
    if run(["docker", "network", "inspect", name], check=False).returncode != 0:
        run(["docker", "network", "create", name])


def save_state():
    APPS_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"net": STATE["net"]}))


def load_state():
    if (NPM_DIR / "docker-compose.yml").exists() and STATE_FILE.exists():
        try:
            net = json.loads(STATE_FILE.read_text()).get("net")
        except ValueError:
            net = None
        if net:
            STATE["net"] = net


def adopt_existing_npm():
    """Apps-only mode: notice an earlier Nginx Proxy Manager and its network."""
    load_state()
    if STATE["net"]:
        info(f"Found Nginx Proxy Manager. New apps will join its Docker network "
             f"'{STATE['net']}' and publish no ports.")
        return
    if not shutil.which("docker"):
        return
    running = run(["docker", "ps", "--filter", "ancestor=jc21/nginx-proxy-manager", "-q"],
                  check=False).stdout.split()
    if not running and not (NPM_DIR / "docker-compose.yml").exists():
        return
    info("I found Nginx Proxy Manager on this server.")
    if not ask_yes_no("Put new apps on a Docker network shared with it (no published ports)?", True):
        return
    net = ask_net_name()
    ensure_network(net)
    for cid in running:
        run(["docker", "network", "connect", net, cid], check=False)
    STATE["net"] = net
    save_state()
    warn(f"NPM was connected to '{net}' just now. Add that network to NPM's own compose file "
         "too, or the link is lost when NPM is recreated.")


# --- compose building blocks ---
def ports_lines(ctx, *mappings):
    """`ports:` for a service - empty when Nginx Proxy Manager fronts the app."""
    if ctx["no_ports"] or not mappings:
        return []
    return ["    ports:"] + [f'      - "{ctx["bind"]}:{host}:{inner}"' for host, inner in mappings]


def nets_lines():
    return ["    networks:", "      - default", "      - shared"]


def net_def_lines(ctx):
    return ["networks:", "  shared:", "    external: true", f"    name: {ctx['net']}"]


def chown_to(user, *paths):
    try:
        pw = pwd.getpwnam(user)
    except (KeyError, TypeError):
        return
    for path in paths:
        os.chown(path, pw.pw_uid, pw.pw_gid)


def compose_up(compose):
    info("Pulling images and starting containers (can take a few minutes)...\n")
    run_live(["docker", "compose", "-f", str(compose), "up", "-d"])


def wait_container(name, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        proc = run(["docker", "inspect", "-f",
                    "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                    name], check=False)
        if proc.returncode == 0:
            status, _, health = proc.stdout.strip().partition("|")
            if status == "running" and health in ("", "healthy"):
                return True
            if status in ("exited", "dead"):
                break
        time.sleep(3)
    logs = run(["docker", "logs", "--tail", "25", name], check=False)
    raise CmdError(f"{name} did not become ready. Last log lines:\n{logs.stdout}{logs.stderr}")


def app_context(app):
    return {
        "key": app["key"], "name": app["name"], "dir": APPS_DIR / app["key"],
        "net": STATE["net"] or DEFAULT_APPS_NET, "no_ports": bool(STATE["net"]),
        "bind": "127.0.0.1", "port": None, "tz": system_tz(),
        "user": STATE["username"], "auto": False, "shown": [],
    }


def choose_exposure(ctx, label, default_port, internal_port):
    """Confirm the port (and who can reach it) before installing. Returns False to skip."""
    if ctx["no_ports"]:
        print(f"\n{label} listens on port {internal_port} inside its container. Its compose file "
              f"publishes no ports; Nginx Proxy Manager reaches it over the Docker network "
              f"'{ctx['net']}'.")
        return True
    port = ask_port(label, default_port)
    if port is None:
        info(f"Skipped {label}.")
        return False
    ctx["port"] = port
    ctx["bind"] = ask_bind(label)
    return True


def confirm_install(ctx, extra_lines=()):
    print(f"\nReady to install {ctx['name']}:")
    print(f"    folder:   {ctx['dir']}")
    if ctx["no_ports"]:
        print(f"    network:  {ctx['net']} (no published ports - reach it through Nginx Proxy Manager)")
    elif ctx["port"]:
        print(f"    address:  {ctx['bind']}:{ctx['port']}")
    for line in extra_lines:
        print("    " + line)
    if not ask_yes_no(f"Install {ctx['name']} now?", True):
        info("Skipped.")
        return False
    return True


def deploy(ctx, lines, env_values, container):
    d = ctx["dir"]
    compose = d / "docker-compose.yml"
    if compose.exists() and not ask_yes_no(
            f"{compose} already exists. Overwrite it? (existing data volumes keep their old "
            "database password)", False):
        info("Skipped.")
        return False
    ensure_network(ctx["net"])
    d.mkdir(parents=True, exist_ok=True)
    compose.write_text("\n".join(lines) + "\n")
    env_file = d / ".env"
    env_file.write_text("".join(f"{k}='{v}'\n" for k, v in env_values.items()))
    env_file.chmod(0o600)
    chown_to(ctx["user"], d, compose, env_file)
    good(f"Wrote {compose} and {env_file} (settings and secrets, readable only by its owner)")
    compose_up(compose)
    wait_container(container)
    good(f"{ctx['name']} is running.")
    SUMMARY.append(f"{ctx['name']} installed ({d})")
    return True


def show_credentials(ctx):
    if not ctx["shown"]:
        return
    print(_c("1;33", "\nSave these now - generated values are also kept in "
             f"{ctx['dir'] / '.env'} (owner-only file):"))
    for label, value in ctx["shown"]:
        print(f"    {label}: {value}")
    print()


def show_access(ctx, label, internal_port, domain=None, websockets=True, extra=None, host=None):
    if ctx["no_ports"]:
        print(f"\n{label} has no published port. In Nginx Proxy Manager, add a Proxy Host:\n"
              f"    Domain Names:        {domain or 'your domain (its DNS must point at this server)'}\n"
              f"    Scheme:              http\n"
              f"    Forward Hostname:    {host or ctx['key']}"
              f"   (the container name)\n"
              f"    Forward Port:        {internal_port}")
        if websockets:
            print("    Websockets Support:  ON")
        print("    SSL tab:             request a Let's Encrypt certificate, enable Force SSL\n")
    else:
        bind, port = ctx["bind"], ctx["port"]
        flag = f"-p {STATE['ssh_port']} " if STATE["ssh_port"] != 22 else ""
        if bind == "127.0.0.1":
            print("\nOpen it through an SSH tunnel. On YOUR LOCAL computer run:\n\n"
                  + _c("1", f"    ssh -L {port}:127.0.0.1:{port} {flag}{ctx['user']}@{server_ip()}")
                  + f"\n\nthen browse to  http://localhost:{port}  (keep that SSH window open).\n")
        elif bind == "0.0.0.0":
            warn(f"{label} is PUBLIC at http://{server_ip()}:{port}")
        else:
            print(f"\n{label}: http://{bind}:{port} (reachable only via that IP).\n")
    if extra:
        info(extra)


# --- helpers for host installs ---
def download_script(url):
    data = urllib.request.urlopen(url, timeout=60).read()
    fd, path = tempfile.mkstemp(suffix=".sh")
    os.write(fd, data)
    os.close(fd)
    os.chmod(path, 0o700)
    return path


def run_remote_installer(url, env_extra=None, shell="sh"):
    script = download_script(url)
    try:
        run_live([shell, script], env_extra=env_extra)
    finally:
        os.unlink(script)


def container_exists(name):
    return name in run(["docker", "ps", "-a", "--format", "{{.Names}}"], check=False).stdout.split()


def ports_busy(ports):
    return [p for p in ports if port_in_use(p)]


# --- the apps ---
def install_n8n(ctx):
    ask_auto(ctx)
    domain = ask_value("Domain for n8n (e.g. n8n.example.com)", required=ctx["no_ports"],
                       validate=v_domain,
                       hint="Used in webhook URLs. Required when Nginx Proxy Manager serves it; "
                            "otherwise Enter to skip (you'll use an SSH tunnel).")
    tz = ask_value("Timezone", default=ctx["tz"])
    enc = ask_value("N8N_ENCRYPTION_KEY", secret=True, generate=True, auto=ctx["auto"],
                    confirm=True,
                    hint="Encrypts the credentials you save in n8n. Back it up - without it a "
                         "restored database can't be decrypted.")
    dbpw = ask_value("Database password", secret=True, generate=True, auto=ctx["auto"], confirm=True)
    if not choose_exposure(ctx, "n8n", 5678, 5678):
        return
    port = ctx["port"]
    if domain:
        host, proto, url, secure = domain, "https", f"https://{domain}/", "true"
    else:
        host, proto, url, secure = "localhost", "http", f"http://localhost:{port}/", "false"
    if not confirm_install(ctx):
        return
    lines = [
        "services:",
        "  postgres:",
        "    image: postgres:16-alpine",
        "    restart: unless-stopped",
        "    environment:",
        "      POSTGRES_USER: n8n",
        "      POSTGRES_PASSWORD: ${DB_PASSWORD}",
        "      POSTGRES_DB: n8n",
        "    volumes:",
        "      - db_data:/var/lib/postgresql/data",
        "    healthcheck:",
        '      test: ["CMD-SHELL", "pg_isready -U n8n -d n8n"]',
        "      interval: 5s",
        "      timeout: 5s",
        "      retries: 10",
        "  n8n:",
        "    image: docker.n8n.io/n8nio/n8n:latest",
        "    container_name: n8n",
        "    restart: unless-stopped",
        *ports_lines(ctx, (port, 5678)),
        "    environment:",
        "      DB_TYPE: postgresdb",
        "      DB_POSTGRESDB_HOST: postgres",
        "      DB_POSTGRESDB_PORT: 5432",
        "      DB_POSTGRESDB_DATABASE: n8n",
        "      DB_POSTGRESDB_USER: n8n",
        "      DB_POSTGRESDB_PASSWORD: ${DB_PASSWORD}",
        "      N8N_ENCRYPTION_KEY: ${N8N_ENCRYPTION_KEY}",
        "      N8N_HOST: ${N8N_HOST}",
        "      N8N_PORT: 5678",
        "      N8N_PROTOCOL: ${N8N_PROTOCOL}",
        "      WEBHOOK_URL: ${WEBHOOK_URL}",
        "      N8N_SECURE_COOKIE: ${N8N_SECURE_COOKIE}",
        "      GENERIC_TIMEZONE: ${TZ}",
        "      TZ: ${TZ}",
        "    volumes:",
        "      - n8n_data:/home/node/.n8n",
        "    depends_on:",
        "      postgres:",
        "        condition: service_healthy",
        *nets_lines(),
        "volumes:",
        "  db_data:",
        "  n8n_data:",
        *net_def_lines(ctx),
    ]
    env = {"DB_PASSWORD": dbpw, "N8N_ENCRYPTION_KEY": enc, "N8N_HOST": host,
           "N8N_PROTOCOL": proto, "WEBHOOK_URL": url, "N8N_SECURE_COOKIE": secure, "TZ": tz}
    if deploy(ctx, lines, env, "n8n"):
        show_access(ctx, "n8n", 5678, domain=domain,
                    extra="n8n asks you to create the owner account on first visit - do it right away.")


def ollama_present():
    return shutil.which("docker") is not None and container_exists("ollama")


def install_ollama(ctx):
    publish = False
    if not ctx["no_ports"]:
        publish = ask_yes_no(
            "Publish Ollama's API on this server's network? (Only needed for tools outside Docker. "
            "Other containers on the shared network can reach it without this. Ollama has NO "
            "login, so never expose it publicly.)", False)
    if publish:
        port = ask_port("Ollama", 11434)
        if port is None:
            publish = False
        else:
            ctx["port"] = port
            ctx["bind"] = ask_bind("the Ollama API", allow_public=False)
    else:
        print("\nOllama listens on port 11434 inside its container; other apps reach it at "
              f"http://ollama:11434 over the Docker network '{ctx['net']}'.")
    model = ask_value("Download a model after installing? Enter a name like llama3.2:3b",
                      validate=v_model,
                      hint="Models are large (a few GB). A CPU-only VPS runs small models slowly. "
                           "Enter to skip - you can run 'docker exec ollama ollama pull <name>' later.")
    if not confirm_install(ctx, [f"model:    {model}" if model else "model:    (none yet)"]):
        return
    lines = [
        "services:",
        "  ollama:",
        "    image: ollama/ollama:latest",
        "    container_name: ollama",
        "    restart: unless-stopped",
        *(ports_lines(ctx, (ctx["port"], 11434)) if publish else []),
        "    volumes:",
        "      - ollama_data:/root/.ollama",
        *nets_lines(),
        "volumes:",
        "  ollama_data:",
        *net_def_lines(ctx),
    ]
    if deploy(ctx, lines, {"TZ": ctx["tz"]}, "ollama"):
        if model:
            info(f"Downloading {model} ...")
            run_live(["docker", "exec", "ollama", "ollama", "pull", model])
        if publish:
            show_access(ctx, "Ollama API", 11434, websockets=False)
        info("Chat with it from the terminal:  docker exec -it ollama ollama run <model>")


def install_open_webui(ctx):
    ask_auto(ctx)
    domain = ask_value("Domain for Open WebUI (e.g. chat.example.com)", required=ctx["no_ports"],
                       validate=v_domain,
                       hint="Required when Nginx Proxy Manager serves it; otherwise Enter to skip "
                            "(you'll use an SSH tunnel).")
    signup = ask_yes_no("Allow anyone who can reach the site to sign up? "
                        "(Open WebUI makes the first account the admin.)", False)
    ollama = ask_value("Ollama URL", default="http://ollama:11434" if ollama_present() else None,
                       validate=v_url,
                       hint="Needs a model backend: an Ollama server and/or an OpenAI-compatible "
                            "API key. You can add more later under Admin > Settings > Connections.")
    openai_key = ask_value("OpenAI-compatible API key", secret=True)
    openai_base = ""
    if openai_key:
        openai_base = ask_value("API base URL", default="https://api.openai.com/v1", validate=v_url)
    if not ollama and not openai_key:
        warn("No model backend set - Open WebUI will start with no models until you add one.")
    secret_key = ask_value("WEBUI_SECRET_KEY", secret=True, generate=True, auto=ctx["auto"],
                           confirm=True, hint="Signs login sessions; keep it stable across restarts.")
    pgpw = ask_value("Database password", secret=True, generate=True, auto=ctx["auto"], confirm=True)
    if not choose_exposure(ctx, "Open WebUI", 8081, 8080):
        return
    url = f"https://{domain}" if domain else f"http://localhost:{ctx['port']}"
    if not confirm_install(ctx, [f"sign-up: {'open' if signup else 'closed'}"]):
        return
    env = {"POSTGRES_PASSWORD": pgpw, "WEBUI_SECRET_KEY": secret_key, "WEBUI_URL": url,
           "ENABLE_SIGNUP": "true" if signup else "false"}
    app_env = [
        "      DATABASE_URL: postgresql://openwebui:${POSTGRES_PASSWORD}@postgres:5432/openwebui",
        "      VECTOR_DB: pgvector",
        "      PGVECTOR_DB_URL: postgresql://openwebui:${POSTGRES_PASSWORD}@postgres:5432/openwebui",
        "      WEBUI_SECRET_KEY: ${WEBUI_SECRET_KEY}",
        "      WEBUI_URL: ${WEBUI_URL}",
        "      ENABLE_SIGNUP: ${ENABLE_SIGNUP}",
    ]
    if ollama:
        env["OLLAMA_BASE_URL"] = ollama
        app_env.append("      OLLAMA_BASE_URL: ${OLLAMA_BASE_URL}")
    if openai_key:
        env["OPENAI_API_KEY"] = openai_key
        env["OPENAI_API_BASE_URL"] = openai_base
        app_env += ["      OPENAI_API_KEY: ${OPENAI_API_KEY}",
                    "      OPENAI_API_BASE_URL: ${OPENAI_API_BASE_URL}"]
    lines = [
        "services:",
        "  postgres:",
        "    image: pgvector/pgvector:pg16",
        "    restart: unless-stopped",
        "    environment:",
        "      POSTGRES_USER: openwebui",
        "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}",
        "      POSTGRES_DB: openwebui",
        "    volumes:",
        "      - postgres_data:/var/lib/postgresql/data",
        "    healthcheck:",
        '      test: ["CMD-SHELL", "pg_isready -U openwebui -d openwebui"]',
        "      interval: 5s",
        "      timeout: 5s",
        "      retries: 10",
        "  open-webui:",
        "    image: ghcr.io/open-webui/open-webui:main",
        "    container_name: open-webui",
        "    restart: unless-stopped",
        *ports_lines(ctx, (ctx["port"], 8080)),
        "    environment:",
        *app_env,
        "    volumes:",
        "      - open_webui_data:/app/backend/data",
        "    depends_on:",
        "      postgres:",
        "        condition: service_healthy",
        *nets_lines(),
        "volumes:",
        "  postgres_data:",
        "  open_webui_data:",
        *net_def_lines(ctx),
    ]
    if deploy(ctx, lines, env, "open-webui"):
        show_access(ctx, "Open WebUI", 8080, domain=domain, websockets=True,
                    extra="Create the admin account first. If sign-up is closed and you can't "
                          "register, set ENABLE_SIGNUP='true' in .env, run 'docker compose up -d', "
                          "register, then set it back.")


def install_gitea(ctx):
    ask_auto(ctx)
    domain = ask_value("Domain for Gitea (e.g. git.example.com)", required=ctx["no_ports"],
                       validate=v_domain,
                       hint="Used in clone URLs. Required when Nginx Proxy Manager serves it; "
                            "otherwise Enter to skip (you'll use an SSH tunnel).")
    admin = ask_value("Gitea admin username", default="gitadmin", validate=v_user_not_reserved,
                      hint="'admin' is reserved by Gitea.")
    email = ask_value("Admin email", required=True, validate=v_email)
    pw = ask_value("Admin password", secret=True, generate=True, gen=gen_password, confirm=True,
                   validate=v_strong, shown=ctx["shown"],
                   hint="Created for you now, so nobody else can claim the admin account first.")
    closed = ask_yes_no("Disable public registration? (recommended for private hosting)", True)
    dbpw = ask_value("Database password", secret=True, generate=True, auto=ctx["auto"], confirm=True)
    if not choose_exposure(ctx, "Gitea (web)", 8082, 3000):
        return
    ssh_port = None
    if ctx["no_ports"]:
        info("Git over SSH needs a published port, so it's off. Use HTTPS clone URLs.")
    else:
        ssh_port = ask_port("Gitea Git-over-SSH", 2222, avoid=(ctx["port"],))
        if ssh_port is None:
            info("Git over SSH disabled; use HTTPS clone URLs.")
    root_url = f"https://{domain}/" if domain else f"http://localhost:{ctx['port']}/"
    if not confirm_install(ctx, [f"git ssh: {ssh_port or 'off'}"]):
        return
    info("Generating Gitea's signing keys (pulls the image first)...")
    secret_key = run(["docker", "run", "--rm", "docker.gitea.com/gitea:latest", "gitea",
                      "generate", "secret", "SECRET_KEY"]).stdout.strip()
    internal = run(["docker", "run", "--rm", "docker.gitea.com/gitea:latest", "gitea",
                    "generate", "secret", "INTERNAL_TOKEN"]).stdout.strip()
    env = {"DB_PASSWORD": dbpw, "GITEA_DOMAIN": domain or "localhost", "GITEA_ROOT_URL": root_url,
           "GITEA_SSH_PORT": str(ssh_port or 22), "GITEA_DISABLE_SSH": "false" if ssh_port else "true",
           "DISABLE_REGISTRATION": "true" if closed else "false",
           "GITEA_SECRET_KEY": secret_key, "GITEA_INTERNAL_TOKEN": internal}
    maps = [(ctx["port"], 3000)] + ([(ssh_port, 22)] if ssh_port else [])
    lines = [
        "services:",
        "  db:",
        "    image: postgres:16-alpine",
        "    restart: unless-stopped",
        "    environment:",
        "      POSTGRES_USER: gitea",
        "      POSTGRES_PASSWORD: ${DB_PASSWORD}",
        "      POSTGRES_DB: gitea",
        "    volumes:",
        "      - db_data:/var/lib/postgresql/data",
        "    healthcheck:",
        '      test: ["CMD-SHELL", "pg_isready -U gitea -d gitea"]',
        "      interval: 5s",
        "      timeout: 5s",
        "      retries: 10",
        "  gitea:",
        "    image: docker.gitea.com/gitea:latest",
        "    container_name: gitea",
        "    restart: unless-stopped",
        *ports_lines(ctx, *maps),
        "    environment:",
        '      USER_UID: "1000"',
        '      USER_GID: "1000"',
        "      GITEA__database__DB_TYPE: postgres",
        "      GITEA__database__HOST: db:5432",
        "      GITEA__database__NAME: gitea",
        "      GITEA__database__USER: gitea",
        "      GITEA__database__PASSWD: ${DB_PASSWORD}",
        "      GITEA__server__DOMAIN: ${GITEA_DOMAIN}",
        "      GITEA__server__SSH_DOMAIN: ${GITEA_DOMAIN}",
        "      GITEA__server__ROOT_URL: ${GITEA_ROOT_URL}",
        "      GITEA__server__SSH_PORT: ${GITEA_SSH_PORT}",
        "      GITEA__server__DISABLE_SSH: ${GITEA_DISABLE_SSH}",
        "      GITEA__service__DISABLE_REGISTRATION: ${DISABLE_REGISTRATION}",
        '      GITEA__security__INSTALL_LOCK: "true"',
        "      GITEA__security__SECRET_KEY: ${GITEA_SECRET_KEY}",
        "      GITEA__security__INTERNAL_TOKEN: ${GITEA_INTERNAL_TOKEN}",
        "    volumes:",
        "      - gitea_data:/data",
        "    depends_on:",
        "      db:",
        "        condition: service_healthy",
        *nets_lines(),
        "volumes:",
        "  db_data:",
        "  gitea_data:",
        *net_def_lines(ctx),
    ]
    if not deploy(ctx, lines, env, "gitea"):
        return
    info("Creating the admin user...")
    end = time.time() + 120
    while run(["docker", "exec", "-u", "git", "gitea", "gitea", "admin", "user", "list"],
              check=False).returncode != 0:
        if time.time() > end:
            raise CmdError("Gitea didn't become ready in time to create the admin user. Create it "
                           "later with: docker exec -u git gitea gitea admin user create --admin ...")
        time.sleep(4)
    run(["docker", "exec", "-u", "git", "gitea", "gitea", "admin", "user", "create", "--admin",
         "--username", admin, "--password", pw, "--email", email, "--must-change-password=false"])
    good(f"Admin user '{admin}' created.")
    show_credentials(ctx)
    show_access(ctx, "Gitea", 3000, domain=domain, websockets=False)


def install_uptime_kuma(ctx):
    if not choose_exposure(ctx, "Uptime Kuma", 3001, 3001):
        return
    if not confirm_install(ctx):
        return
    lines = [
        "services:",
        "  uptime-kuma:",
        "    image: louislam/uptime-kuma:2",
        "    container_name: uptime-kuma",
        "    restart: unless-stopped",
        *ports_lines(ctx, (ctx["port"], 3001)),
        "    volumes:",
        "      - uptime_kuma_data:/app/data",
        *nets_lines(),
        "volumes:",
        "  uptime_kuma_data:",
        *net_def_lines(ctx),
    ]
    if deploy(ctx, lines, {"TZ": ctx["tz"]}, "uptime-kuma"):
        show_access(ctx, "Uptime Kuma", 3001, websockets=True,
                    extra="Uptime Kuma asks you to create the admin account on first visit - do it "
                          "right away, before anyone else can.")


def install_nextcloud(ctx):
    ask_auto(ctx)
    domain = ask_value("Domain for Nextcloud (e.g. cloud.example.com)", required=ctx["no_ports"],
                       validate=v_domain,
                       hint="Required when Nginx Proxy Manager serves it; otherwise Enter to skip "
                            "(you'll use an SSH tunnel).")
    admin = ask_value("Nextcloud admin username", default="admin", validate=v_user_basic)
    pw = ask_value("Nextcloud admin password", secret=True, generate=True, gen=gen_password,
                   confirm=True, validate=v_strong, shown=ctx["shown"])
    dbpw = ask_value("Database password", secret=True, generate=True, auto=ctx["auto"], confirm=True)
    if not choose_exposure(ctx, "Nextcloud", 8083, 80):
        return
    trusted = ["localhost"]
    if ctx["port"]:
        trusted.append(f"localhost:{ctx['port']}")
        hosts = []
        if ctx["bind"] == "0.0.0.0":
            hosts.append(server_ip())
        elif ctx["bind"] != "127.0.0.1":
            hosts.append(ctx["bind"])
        for h in hosts:
            trusted += [h, f"{h}:{ctx['port']}"]
    if domain:
        trusted.append(domain)
    if not confirm_install(ctx):
        return
    env = {"DB_PASSWORD": dbpw, "NC_ADMIN_USER": admin, "NC_ADMIN_PASSWORD": pw,
           "NC_TRUSTED_DOMAINS": " ".join(trusted)}
    app_env = [
        "      POSTGRES_HOST: db",
        "      POSTGRES_DB: nextcloud",
        "      POSTGRES_USER: nextcloud",
        "      POSTGRES_PASSWORD: ${DB_PASSWORD}",
        "      NEXTCLOUD_ADMIN_USER: ${NC_ADMIN_USER}",
        "      NEXTCLOUD_ADMIN_PASSWORD: ${NC_ADMIN_PASSWORD}",
        "      NEXTCLOUD_TRUSTED_DOMAINS: ${NC_TRUSTED_DOMAINS}",
        "      REDIS_HOST: redis",
    ]
    if domain:
        app_env += ["      OVERWRITEHOST: " + domain, "      OVERWRITEPROTOCOL: https"]
    if domain or ctx["no_ports"]:
        app_env.append('      TRUSTED_PROXIES: "172.16.0.0/12 192.168.0.0/16 10.0.0.0/8"')
    lines = [
        "services:",
        "  db:",
        "    image: postgres:16-alpine",
        "    restart: unless-stopped",
        "    environment:",
        "      POSTGRES_USER: nextcloud",
        "      POSTGRES_PASSWORD: ${DB_PASSWORD}",
        "      POSTGRES_DB: nextcloud",
        "    volumes:",
        "      - db_data:/var/lib/postgresql/data",
        "    healthcheck:",
        '      test: ["CMD-SHELL", "pg_isready -U nextcloud -d nextcloud"]',
        "      interval: 5s",
        "      timeout: 5s",
        "      retries: 10",
        "  redis:",
        "    image: redis:7-alpine",
        "    restart: unless-stopped",
        "  nextcloud:",
        "    image: nextcloud:apache",
        "    container_name: nextcloud",
        "    restart: unless-stopped",
        *ports_lines(ctx, (ctx["port"], 80)),
        "    environment:",
        *app_env,
        "    volumes:",
        "      - nextcloud_data:/var/www/html",
        "    depends_on:",
        "      db:",
        "        condition: service_healthy",
        "      redis:",
        "        condition: service_started",
        *nets_lines(),
        "volumes:",
        "  db_data:",
        "  nextcloud_data:",
        *net_def_lines(ctx),
    ]
    if deploy(ctx, lines, env, "nextcloud"):
        show_credentials(ctx)
        show_access(ctx, "Nextcloud", 80, domain=domain, websockets=False,
                    extra="The first start takes a minute or two while Nextcloud sets itself up; "
                          f"log in as '{admin}' with the password above.")


def install_jellyfin(ctx):
    media = ask_value("Folder on this server with your media (movies, TV, music)",
                      default=str(ctx["dir"] / "media"), validate=v_abs_path,
                      hint="Mounted read-only inside Jellyfin. It's created if it doesn't exist.")
    tz = ask_value("Timezone", default=ctx["tz"])
    if not choose_exposure(ctx, "Jellyfin", 8096, 8096):
        return
    if not confirm_install(ctx, [f"media:    {media} (read-only)"]):
        return
    Path(media).mkdir(parents=True, exist_ok=True)
    lines = [
        "services:",
        "  jellyfin:",
        "    image: jellyfin/jellyfin:latest",
        "    container_name: jellyfin",
        "    restart: unless-stopped",
        *ports_lines(ctx, (ctx["port"], 8096)),
        "    environment:",
        "      TZ: ${TZ}",
        "    volumes:",
        "      - jellyfin_config:/config",
        "      - jellyfin_cache:/cache",
        '      - "${MEDIA_DIR}:/media:ro"',
        *nets_lines(),
        "volumes:",
        "  jellyfin_config:",
        "  jellyfin_cache:",
        *net_def_lines(ctx),
    ]
    if deploy(ctx, lines, {"MEDIA_DIR": media, "TZ": tz}, "jellyfin"):
        show_access(ctx, "Jellyfin", 8096, websockets=True,
                    extra="Jellyfin's setup wizard has no login until you finish it - complete it "
                          "right away.")


def install_tailscale(ctx):
    if shutil.which("tailscale"):
        info("Tailscale is already installed.")
    else:
        url = "https://tailscale.com/install.sh"
        print(f"\nThis downloads and runs Tailscale's official installer ({url}) as root.")
        if not ask_yes_no("Continue?", True):
            info("Skipped.")
            return
        run_remote_installer(url)
    run(["systemctl", "enable", "--now", "tailscaled"], check=False)
    ip = tailscale_ip()
    if ip:
        good(f"Tailscale is connected. This server's tailnet IP: {ip}")
    elif ask_yes_no("Log this server in to Tailscale now?", True):
        use_ssh = ask_yes_no("Enable Tailscale SSH (log in over the tailnet, no keys to manage)?",
                             False)
        print("\nOpen the login link shown below in a browser and approve this machine "
              "(Ctrl+C to skip):\n")
        try:
            run_live(["tailscale", "up"] + (["--ssh"] if use_ssh else []))
        except (CmdError, KeyboardInterrupt):
            warn("Login not finished. Run  sudo tailscale up  later.")
        ip = tailscale_ip()
        if ip:
            good(f"Connected. This server's tailnet IP: {ip}")
            info("Choose this IP when an app asks for 'a specific IP' to keep it tailnet-only.")
    if tailscale_ip() and STATE["ufw"] and ask_yes_no(
            "Allow all traffic arriving over the tailnet in UFW (ufw allow in on tailscale0)? "
            "Only your own devices can use it.", True):
        run(["ufw", "allow", "in", "on", "tailscale0"], check=False)
        ufw_reload()
        good("UFW now allows tailnet traffic.")
    SUMMARY.append("Tailscale installed" + (f" (tailnet IP {tailscale_ip()})" if tailscale_ip() else ""))


def install_coolify(ctx):
    busy = ports_busy((80, 443, 8000, 6001, 6002))
    if busy:
        warn("Coolify needs ports 80, 443, 8000, 6001 and 6002, but these are in use: "
             + ", ".join(str(p) for p in busy) + ". Skipping Coolify.")
        return
    if memory_gb() and memory_gb() < 1.8:
        warn(f"This server has about {memory_gb():.1f} GB of RAM; Coolify recommends at least 2 GB.")
        if not ask_yes_no("Install anyway?", False):
            return
    try:
        root_login = (effective().get("permitrootlogin") or [""])[0]
    except CmdError:
        root_login = ""
    if root_login == "no":
        warn("Root SSH login is disabled. Coolify manages this server over SSH as root, so its "
             "built-in server may show as unreachable. 'prohibit-password' (key-only) works.")
        if not ask_yes_no("Install anyway?", False):
            return
    print(
        "\nCoolify runs its own installer, takes over ports 80/443 and publishes its dashboard on "
        "port 8000 to the INTERNET. Docker ignores UFW for those ports. Coolify's docs list "
        "root access as a requirement for the automated install.\n")
    user = ask_value("Coolify admin username", default="admin",
                     validate=lambda v: None if re.match(r"^[A-Za-z0-9 _-]{3,255}$", v)
                     else "Use 3-255 letters, digits, spaces, '_' or '-'.")
    email = ask_value("Admin email (must be a real domain)", required=True, validate=v_email)
    pw = ask_value("Admin password", secret=True, generate=True, gen=gen_password, confirm=True,
                   validate=v_strong, shown=ctx["shown"],
                   hint="Created during install so nobody can claim the admin account first.")
    url = "https://cdn.coollabs.io/coolify/install.sh"
    print(f"\nThis downloads and runs Coolify's official installer ({url}) as root.")
    if not ask_yes_no("Install Coolify now?", True):
        info("Skipped.")
        return
    run_remote_installer(url, env_extra={"ROOT_USERNAME": user, "ROOT_USER_EMAIL": email,
                                         "ROOT_USER_PASSWORD": pw}, shell="bash")
    show_credentials(ctx)
    info(f"Coolify dashboard: http://{server_ip()}:8000  (log in with the email above).")
    warn("Add a domain with HTTPS in Coolify's settings soon; port 8000 is open to the internet.")
    SUMMARY.append("Coolify installed (dashboard on port 8000)")


def install_dokploy(ctx):
    busy = ports_busy((80, 443, 3000))
    if busy:
        warn("Dokploy needs ports 80, 443 and 3000, but these are in use: "
             + ", ".join(str(p) for p in busy) + ". Skipping Dokploy.")
        return
    if memory_gb() and memory_gb() < 1.8:
        warn(f"This server has about {memory_gb():.1f} GB of RAM; Dokploy recommends at least 2 GB.")
        if not ask_yes_no("Install anyway?", False):
            return
    print(
        "\nDokploy runs its own installer, takes over ports 80/443 and publishes its dashboard on "
        "port 3000 to the INTERNET (Docker ignores UFW for those ports). The first person to "
        "open the page creates the admin account - so open it the moment the install finishes.\n")
    url = "https://dokploy.com/install.sh"
    print(f"This downloads and runs Dokploy's official installer ({url}) as root.")
    if not ask_yes_no("Install Dokploy now?", True):
        info("Skipped.")
        return
    run_remote_installer(url)
    warn(f"Open http://{server_ip()}:3000 NOW and create the admin account.")
    SUMMARY.append("Dokploy installed (dashboard on port 3000 - create the admin account now)")


def compose_supports_override():
    out = run(["docker", "compose", "version", "--short"], check=False).stdout.strip().lstrip("v")
    parts = tuple(int(x) for x in re.findall(r"\d+", out)[:3])
    return parts >= (2, 24, 4)


def published_ports(name_filter):
    return run(["docker", "ps", "--filter", f"name={name_filter}", "--format",
                "{{.Names}}: {{.Ports}}"], check=False).stdout.strip()


def install_openclaw(ctx):
    ask_auto(ctx)
    tz = ask_value("Timezone", default=ctx["tz"])
    token = ask_value("OPENCLAW_GATEWAY_TOKEN", secret=True, generate=True, auto=ctx["auto"],
                      confirm=True, validate=v_min(16), shown=ctx["shown"],
                      hint="The password for OpenClaw's gateway/dashboard.")
    provider_vars = ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY"]
    pick = ask_choice(
        "\nWhich model provider's API key do you want to give OpenClaw? (It needs at least one "
        "to answer anything; the setup wizard can also collect this.)",
        ["OpenAI", "Anthropic", "Google Gemini", "OpenRouter", "Skip - I'll enter it in the wizard"],
        5)
    extra_env = {}
    if pick <= 4:
        key = ask_value(provider_vars[pick - 1], secret=True, required=True)
        extra_env[provider_vars[pick - 1]] = key
    tg = ask_value("TELEGRAM_BOT_TOKEN (optional, to chat with OpenClaw on Telegram)", secret=True)
    if tg:
        extra_env["TELEGRAM_BOT_TOKEN"] = tg
    if not choose_exposure(ctx, "OpenClaw gateway", 18789, 18789):
        return
    print("\nNext, OpenClaw's own setup wizard runs. It asks for your model provider API key "
          "and chat channels - you'll answer its prompts directly. OpenClaw can act on its host "
          "and treats incoming chat messages as untrusted; read its security guide before "
          "connecting other people.")
    if not confirm_install(ctx, ["image:    ghcr.io/openclaw/openclaw:latest",
                                 "source:   github.com/openclaw/openclaw (official setup script)"]):
        return
    base = ctx["dir"]
    src, data = base / "src", base / "data"
    if not shutil.which("git"):
        apt_install("git")
    base.mkdir(parents=True, exist_ok=True)
    if (src / ".git").exists():
        run(["git", "-C", str(src), "pull", "--ff-only"], check=False)
    else:
        info("Downloading OpenClaw's setup files...")
        run(["git", "clone", "--depth", "1", "https://github.com/openclaw/openclaw.git", str(src)])
    setup = src / "scripts" / "docker" / "setup.sh"
    if not setup.exists():
        raise CmdError(f"{setup} is missing - OpenClaw's repository layout may have changed.")
    ensure_network(ctx["net"])
    override = src / "docker-compose.override.yml"
    can_override = compose_supports_override()
    if can_override and not override.exists():
        if ctx["no_ports"]:
            ports = ["    ports: !override []"]
        else:
            ports = ["    ports: !override", f'      - "{ctx["bind"]}:{ctx["port"]}:18789"']
        override.write_text("\n".join([
            "# Written by vps_setup.py: controls who can reach the gateway.",
            "services:", "  openclaw-gateway:", *ports, *nets_lines(), *net_def_lines(ctx)]) + "\n")
    elif not can_override:
        warn("This Docker Compose is older than 2.24.4, so I can't restrict OpenClaw's published "
             "ports. Its own compose file publishes them on all interfaces - Docker ignores UFW.")
    for sub in ("config", "workspace", "auth-profile-secrets"):
        (data / sub).mkdir(parents=True, exist_ok=True)
        os.chown(data / sub, 1000, 1000)  # the image runs as user 'node' (uid 1000)
    os.chown(data, 1000, 1000)
    env = {"OPENCLAW_IMAGE": "ghcr.io/openclaw/openclaw:latest", "OPENCLAW_GATEWAY_TOKEN": token,
           "OPENCLAW_GATEWAY_PORT": str(ctx["port"] or 18789), "OPENCLAW_GATEWAY_BIND": "lan",
           "OPENCLAW_TZ": tz, "OPENCLAW_CONFIG_DIR": str(data / "config"),
           "OPENCLAW_WORKSPACE_DIR": str(data / "workspace"),
           "OPENCLAW_AUTH_PROFILE_SECRET_DIR": str(data / "auth-profile-secrets")}
    print()
    run_live(["bash", str(setup)], env_extra=env, cwd=str(src))
    env_file = src / ".env"
    existing = env_file.read_text() if env_file.exists() else ""
    have = {ln.split("=", 1)[0].strip() for ln in existing.splitlines() if "=" in ln}
    add = [f"{k}={v}" for k, v in extra_env.items() if k not in have]
    if add:
        with env_file.open("a") as fh:
            fh.write(("" if existing.endswith("\n") or not existing else "\n") + "\n".join(add) + "\n")
        info("Saved your API key(s) to " + str(env_file))
    if env_file.exists():
        env_file.chmod(0o600)
    # The compose file reads these paths/ports from the environment, so pass them again.
    run_live(["docker", "compose", "up", "-d", "--force-recreate", "openclaw-gateway"],
             env_extra=env, cwd=str(src))
    published = published_ports("openclaw")
    if published:
        print("\nPublished ports now:\n" + published)
    if ctx["no_ports"] and "->" in published:
        warn("OpenClaw is still publishing ports. Check " + str(override) + " and run "
             "'docker compose up -d' in " + str(src) + ".")
    elif not ctx["no_ports"] and ctx["bind"] != "0.0.0.0" and "0.0.0.0:" in published:
        warn("Some OpenClaw ports are still open on all interfaces (its bridge/Teams ports). "
             "Review them above.")
    good("OpenClaw gateway is running.")
    SUMMARY.append(f"OpenClaw installed ({src})")
    show_credentials(ctx)
    show_access(ctx, "OpenClaw", 18789, websockets=True, host="openclaw-gateway",
                extra="In the dashboard's Settings, paste the gateway token (also in "
                      f"{src / '.env'}).")


def install_hermes(ctx):
    """Hermes Agent: ONE container (gateway + optional dashboard, supervised inside the image).

    Based on the official Docker docs: `gateway run`, HERMES_DASHBOARD=1 for the dashboard
    (port 9119, which refuses to start on a non-loopback bind without an auth provider),
    and an optional OpenAI-compatible API server on 8642 (API_SERVER_* variables)."""
    image = "nousresearch/hermes-agent:latest"
    if memory_gb() and memory_gb() < 1.0:
        warn(f"This server has about {memory_gb():.1f} GB of RAM; Hermes needs at least 1 GB "
             "(2 GB or more if you use its browser tools).")
        if not ask_yes_no("Install anyway?", False):
            return
    tz = ask_value("Timezone", default=ctx["tz"])

    # -- dashboard (needs a login, so the credentials are asked BEFORE installing) --
    dash = ask_yes_no(
        "Also run Hermes' web dashboard (port 9119)? It manages your API keys, so it gets a "
        "username/password login." + (" Behind Nginx Proxy Manager, also add an Access List."
                                      if ctx["no_ports"] else ""),
        not ctx["no_ports"])
    dash_user = dash_pw = dash_secret = ""
    dash_port, dash_bind = None, "127.0.0.1"
    if dash:
        dash_user = ask_value("Dashboard username", default="hermes-admin", validate=v_user_basic)
        dash_pw = ask_value("Dashboard password", secret=True, generate=True, gen=gen_password,
                            confirm=True, validate=v_strong, shown=ctx["shown"],
                            hint="Hermes refuses to start the dashboard without a login.")
        dash_secret = gen_secret()
        if ctx["no_ports"]:
            choose_exposure(ctx, "Hermes dashboard", 9119, 9119)
        else:
            dash_port = ask_port("the Hermes dashboard", 9119)
            if dash_port is None:
                info("Dashboard skipped.")
                dash = False
            else:
                dash_bind = ask_bind("the Hermes dashboard", allow_public=False)

    # -- optional OpenAI-compatible API server --
    api = ask_yes_no(
        "Enable Hermes' OpenAI-compatible API server (port 8642)? Only needed if other tools "
        "(e.g. Open WebUI) should talk to Hermes.", False)
    api_key = ""
    api_port, api_bind = None, "127.0.0.1"
    if api:
        api_key = ask_value("API_SERVER_KEY", secret=True, generate=True, confirm=True,
                            validate=v_min(8), shown=ctx["shown"],
                            hint="Clients send this as the API key. 8+ characters.")
        if ctx["no_ports"]:
            print(f"\nThe API server stays internal: other containers on '{ctx['net']}' reach it "
                  "at http://hermes:8642/v1")
        else:
            api_port = ask_port("the Hermes API server", 8642,
                                avoid=(dash_port,) if dash_port else ())
            if api_port is None:
                info("API server skipped.")
                api = False
            else:
                api_bind = ask_bind("the Hermes API server", allow_public=False)

    wizard = ask_yes_no("Run Hermes' setup wizard now? It asks for your LLM provider API key "
                        "and chat platform tokens and stores them in its data folder. Without "
                        "it the agent has no model to use.", True)
    extra = [f"image:     {image}",
             f"dashboard: {'yes' if dash else 'no'}" + (f" ({dash_bind}:{dash_port})" if dash_port else ""),
             f"API:       {'yes' if api else 'no'}" + (f" ({api_bind}:{api_port})" if api_port else "")]
    ctx["port"] = None  # per-service addresses are listed above
    if not confirm_install(ctx, extra):
        return

    base = ctx["dir"]
    data = base / "data"
    data.mkdir(parents=True, exist_ok=True)
    os.chown(data, 10000, 10000)  # the image runs as uid 10000
    if wizard:
        print("\nHermes setup wizard (answer its prompts):\n")
        run_live(["docker", "run", "-it", "--rm", "-v", f"{data}:/opt/data", image, "setup"])
    else:
        warn("Skipping the wizard. Run it later with:  docker run -it --rm -v "
             f"{data}:/opt/data {image} setup")

    ports = []
    if not ctx["no_ports"]:
        if dash:
            ports.append(f'      - "{dash_bind}:{dash_port}:9119"')
        if api:
            ports.append(f'      - "{api_bind}:{api_port}:8642"')
    env_lines = ['      TZ: ${TZ}']
    env = {"TZ": tz}
    if dash:
        env.update(HERMES_DASHBOARD_BASIC_AUTH_USERNAME=dash_user,
                   HERMES_DASHBOARD_BASIC_AUTH_PASSWORD=dash_pw,
                   HERMES_DASHBOARD_BASIC_AUTH_SECRET=dash_secret)
        env_lines += ['      HERMES_DASHBOARD: "1"',
                      "      HERMES_DASHBOARD_BASIC_AUTH_USERNAME: ${HERMES_DASHBOARD_BASIC_AUTH_USERNAME}",
                      "      HERMES_DASHBOARD_BASIC_AUTH_PASSWORD: ${HERMES_DASHBOARD_BASIC_AUTH_PASSWORD}",
                      "      HERMES_DASHBOARD_BASIC_AUTH_SECRET: ${HERMES_DASHBOARD_BASIC_AUTH_SECRET}"]
    if api:
        env["API_SERVER_KEY"] = api_key
        env_lines += ['      API_SERVER_ENABLED: "true"', '      API_SERVER_HOST: "0.0.0.0"',
                      "      API_SERVER_KEY: ${API_SERVER_KEY}"]
    lines = ["services:", "  hermes:", f"    image: {image}", "    container_name: hermes",
             "    restart: unless-stopped", "    command: gateway run", '    shm_size: "1gb"']
    if ports:
        lines += ["    ports:"] + ports
    lines += ["    environment:", *env_lines, "    volumes:", "      - ./data:/opt/data"]
    lines += nets_lines() + net_def_lines(ctx)
    if deploy(ctx, lines, env, "hermes"):
        chown_to(ctx["user"], base)
        os.chown(data, 10000, 10000)
        show_credentials(ctx)
        info("The chat gateway makes outbound connections only. Logs:  docker logs -f hermes")
        if dash:
            show_access(ctx, "Hermes dashboard", 9119, websockets=True, host="hermes",
                        extra="Log in with the dashboard username/password above. That login is "
                              "not meant for direct public exposure - keep it private"
                              + (", or protect it with an NPM Access List. If sign-in misbehaves "
                                 "behind the proxy, set dashboard.public_url and "
                                 f"dashboard.trusted_proxies in {data / 'config.yaml'}."
                                 if ctx["no_ports"] else "."))
        if api and ctx["no_ports"]:
            info("API for other containers: http://hermes:8642/v1 (use the API_SERVER_KEY above).")


def step_npm_entry(ctx):
    install_npm()


APPS = [
    dict(key="n8n", name="n8n", desc="Workflow automation", order=40, docker=True, install=install_n8n),
    dict(key="coolify", name="Coolify", desc="Application hosting (uses ports 80/443)", order=90,
         docker=False, platform=True, install=install_coolify),
    dict(key="dokploy", name="Dokploy", desc="Deployment platform (uses ports 80/443)", order=91,
         docker=False, platform=True, install=install_dokploy),
    dict(key="open-webui", name="Open WebUI", desc="AI chat interface", order=30, docker=True,
         install=install_open_webui),
    dict(key="ollama", name="Ollama", desc="Local AI models", order=20, docker=True,
         install=install_ollama),
    dict(key="gitea", name="Gitea", desc="Private Git hosting", order=50, docker=True,
         install=install_gitea),
    dict(key="uptime-kuma", name="Uptime Kuma", desc="Website monitoring", order=60, docker=True,
         install=install_uptime_kuma),
    dict(key="nextcloud", name="Nextcloud", desc="File sync and collaboration", order=70, docker=True,
         install=install_nextcloud),
    dict(key="jellyfin", name="Jellyfin", desc="Media server", order=80, docker=True,
         install=install_jellyfin),
    dict(key="tailscale", name="Tailscale", desc="Private network / VPN", order=5, docker=False,
         install=install_tailscale),
    dict(key="openclaw", name="OpenClaw", desc="Personal AI assistant (chat channels)", order=45,
         docker=True, install=install_openclaw),
    dict(key="hermes", name="Hermes Agent", desc="Self-improving AI agent (Nous Research)", order=46,
         docker=True, install=install_hermes),
    dict(key="npm", name="Nginx Proxy Manager", desc="Reverse proxy + free SSL certificates",
         order=10, docker=True, platform=True, apps_only=True, install=step_npm_entry),
]


def pick_apps(include_npm):
    entries = [a for a in APPS if include_npm or not a.get("apps_only")]
    print("\nPick the apps to install:\n")
    for i, app in enumerate(entries, 1):
        print(f"  {i:>2}) {app['name']:<22} {app['desc']}")
    while True:
        answer = input("\nEnter numbers separated by commas (e.g. 1,4,7), 'all', or press Enter "
                       "to skip: ").strip().lower()
        if not answer:
            return []
        if answer == "all":
            chosen = list(entries)
        else:
            try:
                nums = sorted({int(x) for x in re.split(r"[,\s]+", answer) if x})
            except ValueError:
                warn("Type numbers like 1,4,7.")
                continue
            if not nums or nums[0] < 1 or nums[-1] > len(entries):
                warn(f"Choose numbers between 1 and {len(entries)}.")
                continue
            chosen = [entries[n - 1] for n in nums]
        print("\nSelected: " + ", ".join(a["name"] for a in chosen))
        if ask_yes_no("Is that right?", True):
            return chosen


def resolve_conflicts(chosen):
    """Nginx Proxy Manager, Coolify and Dokploy all need ports 80/443: keep only one."""
    platforms = [a for a in chosen if a.get("platform")]
    if len(platforms) > 1:
        names = [a["name"] for a in platforms]
        warn("These all need ports 80/443 and can't run together: " + ", ".join(names))
        keep = ask_choice("Which one do you want?", names, 1)
        dropped = [a for a in platforms if a["name"] != names[keep - 1]]
        chosen = [a for a in chosen if a not in dropped]
    return chosen


def step_apps(include_npm=False, header="Install optional apps"):
    title("Apps" if include_npm else 10, header)
    print("Docker apps get their own folder under /opt/apps/<app> with a docker-compose.yml and an "
          "owner-only .env file for secrets. You confirm each app's port before it is installed.")
    chosen = pick_apps(include_npm)
    if not chosen:
        info("No apps selected.")
        return
    chosen = sorted(resolve_conflicts(chosen), key=lambda a: a["order"])
    need_docker = [a for a in chosen if a["docker"]]
    if need_docker and not shutil.which("docker"):
        warn("These apps run in Docker, which isn't installed: "
             + ", ".join(a["name"] for a in need_docker))
        if ask_yes_no("Install Docker now?", True):
            install_docker()
        else:
            chosen = [a for a in chosen if not a["docker"]]
    for app in chosen:
        title(app["name"], app["desc"])
        run_step(lambda a=app: a["install"](app_context(a)))


def detect_login_user():
    candidates = [u.pw_name for u in pwd.getpwall()
                  if 1000 <= u.pw_uid < 60000 and u.pw_shell not in ("/usr/sbin/nologin", "/bin/false")]
    return os.environ.get("SUDO_USER") or (candidates[0] if candidates else "root")


def apps_only_mode():
    title("Apps", "Install apps only")
    default = detect_login_user()
    while True:
        name = input(f"Which user should own the app folders (used in connection instructions)? "
                     f"[{default}]: ").strip() or default
        try:
            pwd.getpwnam(name)
            break
        except KeyError:
            warn(f"There is no user called '{name}'.")
    STATE["username"] = name
    STATE["ssh_port"] = (current_ssh_ports() or [22])[0]
    STATE["ufw"] = bool(shutil.which("ufw"))
    try:
        apt_update()
    except CmdError:
        warn("apt update failed; continuing anyway.")
    adopt_existing_npm()
    step_apps(include_npm=True, header="Install apps")


def apps_summary():
    print("\n" + _c("1;32", "=== All done ==="))
    for line in SUMMARY:
        good(line)
    print(
        "\nReminders:\n"
        "  - Docker bypasses UFW for published ports. Apps bound to 127.0.0.1 (or sitting behind "
        "Nginx Proxy Manager with no ports) are the private ones.\n"
        "  - Each app's settings and secrets live in /opt/apps/<app>/.env (owner-only).\n"
        "  - Check what is exposed any time with:  sudo ss -tlnp\n"
    )


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def run_step(func):
    try:
        func()
    except CmdError as exc:
        bad(str(exc))
        if not ask_yes_no("That step failed. Continue with the next step anyway?", False):
            sys.exit(1)


def final_summary():
    print("\n" + _c("1;32", "=== All done ==="))
    for line in SUMMARY:
        good(line)
    try:
        eff = effective()
        print()
        info("Effective SSH settings: "
             f"port={','.join(eff.get('port', ['?']))}  "
             f"permitrootlogin={(eff.get('permitrootlogin') or ['?'])[0]}  "
             f"passwordauthentication={(eff.get('passwordauthentication') or ['?'])[0]}")
    except CmdError:
        pass
    user, port = STATE["username"], STATE["ssh_port"]
    print("\nConnect with:\n\n" + _c("1", f"    ssh {'-p ' + str(port) + ' ' if port != 22 else ''}{user}@{server_ip()}"))
    print(
        "\nReminders:\n"
        "  - Keep this session open until you've confirmed a login in a new terminal.\n"
        "  - Docker bypasses UFW for published ports. In compose files, leave out `ports:` "
        "or bind to 127.0.0.1 unless you really want a service public.\n"
        "  - Check what is exposed any time with:  sudo ss -tlnp\n"
        "  - Backups of the original sshd configs are next to them as *.bak-" + TS + "\n"
    )


def main():
    if os.geteuid() != 0:
        bad("Please run this script as root (log in as root, or use: sudo python3 vps_setup.py).")
        sys.exit(1)
    if not shutil.which("apt-get"):
        bad("This script supports Debian/Ubuntu (apt) only.")
        sys.exit(1)

    splash()
    mode = ask_choice(
        "\nWhat would you like to do?",
        [
            "Full VPS setup: updates, fail2ban, UFW, sudo user, SSH hardening, Docker, "
            "Nginx Proxy Manager, then optional apps",
            "Apps only: my VPS is already set up - just install Docker apps",
        ],
        1,
    )
    if mode == 2:
        run_step(apps_only_mode)
        apps_summary()
        return

    print(
        "\nFull setup, step by step:\n"
        "  0. update the system (apt update && apt upgrade)\n"
        "  1. install fail2ban for SSH\n"
        "  2. enable the UFW firewall (asks before installing it)\n"
        "  3. create a sudo user\n"
        "  4. set up + test SSH key login\n"
        "  5. restrict root login\n"
        "  6. disable password logins\n"
        "  7. change the SSH port\n"
        "  8. install Docker + Compose\n"
        "  9. install Nginx Proxy Manager\n"
        " 10. install optional apps (n8n, Coolify, Dokploy, Open WebUI, Ollama, Gitea,\n"
        "      Uptime Kuma, Nextcloud, Jellyfin, Tailscale, OpenClaw, Hermes)\n\n"
        "Steps 4-10 are optional and ask first. Keep this SSH session open the whole time.\n"
    )

    run_step(step_system_update)
    run_step(step_fail2ban)
    run_step(step_ufw)
    run_step(step_user)
    if not STATE["username"]:
        bad("No sudo user was created, so the remaining steps can't continue safely.")
        sys.exit(1)
    run_step(step_ssh_key)
    run_step(step_root_login)
    run_step(step_password_auth)
    run_step(step_port)
    run_step(step_docker)
    run_step(step_npm)
    run_step(step_apps)
    final_summary()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n\nStopped. Anything already applied stays in place; re-run the script to continue.")
        sys.exit(130)
