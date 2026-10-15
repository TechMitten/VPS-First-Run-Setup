# VPS First-Run Setup

An interactive, single-file Python script that takes a fresh Debian or Ubuntu VPS from "just provisioned" to "hardened and running apps", step by step.

It handles system updates, fail2ban, the UFW firewall, a sudo user, SSH key login, SSH hardening, Docker, and Nginx Proxy Manager, and can then install a selection of self-hosted apps. Every risky step asks first, and the SSH changes are validated and rolled back if they fail, so you don't lock yourself out.

```
==============================================================
   VPS FIRST-RUN SETUP

   MIT License
   github.com/techmitten
==============================================================
```

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Modes](#modes)
- [What the Full Setup Does](#what-the-full-setup-does)
- [Optional Apps](#optional-apps)
- [Networking and Exposure](#networking-and-exposure)
- [Files and Locations](#files-and-locations)
- [Safety Features](#safety-features)
- [After Setup](#after-setup)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **No dependencies.** One file, Python 3 standard library only.
- **Interactive and guided.** Plain-language prompts, with sensible defaults you can accept by pressing Enter.
- **SSH hardening that won't lock you out.** Every `sshd` change is checked with `sshd -t` and verified with `sshd -T`, and rolled back if either check fails.
- **Live key-login test.** Before passwords are disabled, the script waits while you log in with your key from a new terminal, then looks in the server logs to confirm the key login worked.
- **Handles Ubuntu 24.04's `ssh.socket`.** Port changes also update the systemd socket, which ignores `Port` in `sshd_config`.
- **Firewall-aware.** UFW and fail2ban are kept in step with the SSH port.
- **Docker apps that are private by default.** Each app is bound to `127.0.0.1`, or, when Nginx Proxy Manager is installed, publishes no ports at all.
- **Secrets stay out of compose files.** Passwords and keys are generated for you and stored in an owner-only `.env` file for each app.
- **Apps-only mode** for servers that are already set up.

## Requirements

| Requirement | Details |
|---|---|
| OS | Debian or Ubuntu (any release with `apt-get` and systemd) |
| Python | Python 3.8 or newer (preinstalled on current Debian/Ubuntu) |
| Privileges | Must be run as `root` (or with `sudo`) |
| Access | An SSH session to the server, plus a second terminal on your local computer for testing logins |
| Network | Outbound internet access (apt, Docker's repository, container images) |

Some apps need more resources: Coolify and Dokploy recommend 2 GB of RAM or more, and Hermes Agent needs at least 1 GB.

## Quick Start

SSH into your new server as root, download the script, and run it:

```bash
curl -fsSLO https://raw.githubusercontent.com/techmitten/vps-setup/main/vps_setup.py
```

```bash
python3 vps_setup.py
```

Or, as a non-root user with sudo access:

```bash
sudo python3 vps_setup.py
```

> **Important:** Keep your current SSH session open for the whole run. Don't close it until you've confirmed you can log in from a **new** terminal.

## Modes

When the script starts, it asks what you want to do:

1. **Full VPS setup.** Runs every step below in order, from system updates to optional apps.
2. **Apps only.** For a server that's already set up. Skips steps 0 to 9 and goes straight to the app installer. It detects your login user, your SSH port, and any existing Nginx Proxy Manager install.

## What the Full Setup Does

| Step | What happens | Optional? |
|---|---|---|
| 0 | `apt update && apt upgrade`, and offers a reboot if one is needed | No |
| 1 | Installs fail2ban with an `sshd` jail: 5 failed logins in 10 minutes means a 1-hour ban, longer for repeat offenders. Your current IP is whitelisted. | No |
| 2 | Enables UFW: deny incoming, allow outgoing, allow `22/tcp` and any other port `sshd` currently uses. Asks before installing UFW. | No |
| 3 | Creates a sudo user (or updates an existing one) with a password you choose | No |
| 4 | Sets up SSH key login for that user, with help for local file permissions and a live login test | Yes |
| 5 | Restricts root login: disable it completely, or allow keys only | Yes |
| 6 | Disables password logins in `sshd_config` **and** in every drop-in file. Only runs once a key is installed and tested. | Yes |
| 7 | Changes the SSH port, and updates UFW, fail2ban and `ssh.socket` to match | Yes |
| 8 | Installs Docker Engine and the Docker Compose plugin from Docker's official repository | Yes |
| 9 | Installs Nginx Proxy Manager and creates a shared Docker network for apps | Yes |
| 10 | Lets you pick and install optional apps | Yes |

If a step fails, the script shows the error and asks whether to carry on with the next step.

## Optional Apps

Pick any combination by number (for example `1,4,7`), or type `all`. Every app asks for the settings it needs (domains, passwords, API keys) **before** installing anything, and you confirm its port.

| App | Description | Install method | Default port |
|---|---|---|---|
| [Tailscale](https://tailscale.com) | Private network / VPN | Official installer | n/a |
| [Nginx Proxy Manager](https://nginxproxymanager.com)\* | Reverse proxy + free SSL certificates | Docker | 80, 443, 81 (admin) |
| [Ollama](https://ollama.com) | Local AI models | Docker | 11434 (internal by default) |
| [Open WebUI](https://openwebui.com) | AI chat interface (with PostgreSQL + pgvector) | Docker | 8081 |
| [n8n](https://n8n.io) | Workflow automation (with PostgreSQL) | Docker | 5678 |
| [OpenClaw](https://github.com/openclaw/openclaw) | Personal AI assistant with chat channels | Docker (official setup script) | 18789 |
| [Hermes Agent](https://github.com/NousResearch) | Self-improving AI agent by Nous Research | Docker | 9119 (dashboard), 8642 (API) |
| [Gitea](https://gitea.com) | Private Git hosting (with PostgreSQL) | Docker | 8082 (web), 2222 (Git over SSH) |
| [Uptime Kuma](https://uptime.kuma.pet) | Website monitoring | Docker | 3001 |
| [Nextcloud](https://nextcloud.com) | File sync and collaboration (with PostgreSQL + Redis) | Docker | 8083 |
| [Jellyfin](https://jellyfin.org) | Media server | Docker | 8096 |
| [Coolify](https://coolify.io) | Application hosting platform | Official installer | 80, 443, 8000 |
| [Dokploy](https://dokploy.com) | Deployment platform | Official installer | 80, 443, 3000 |

\* In the app list only in apps-only mode. In full setup, it's step 9.

**Conflicts:** Nginx Proxy Manager, Coolify and Dokploy all need ports 80 and 443. If you pick more than one, the script asks you to keep just one.

**Install order:** Apps install in a sensible order whatever order you pick them in. For example, Tailscale goes first so its IP can be used for binding, and Ollama goes before Open WebUI so Open WebUI can find it automatically.

**Admin accounts:** Where the app supports it (Gitea, Nextcloud, Coolify), the admin account is created during install so nobody else can claim it first. For apps that make the first visitor the admin (n8n, Uptime Kuma, Jellyfin, Dokploy, Open WebUI), the script reminds you to set it up straight away.

## Networking and Exposure

Docker **bypasses UFW** for published ports. So this script controls who can reach each app through the address its port is bound to.

### Without Nginx Proxy Manager

For each app you choose who can reach it:

1. **Only this server (`127.0.0.1`).** Recommended. Open it through an SSH tunnel; the script prints the exact command, for example:
   ```bash
   ssh -L 5678:127.0.0.1:5678 youruser@your.server.ip
   ```
2. **A specific IP on this server**, such as your Tailscale IP, so only your tailnet can reach it.
3. **Everyone on the internet.** Not recommended; the script asks you to confirm.

### With Nginx Proxy Manager

You name a shared Docker network (`proxy` by default). Apps you install afterwards join that network and **publish no ports**. Nginx Proxy Manager reaches them by container name (for example `http://n8n:5678`), so the proxy is the only thing exposed.

After each install, the script prints the Proxy Host settings to enter in Nginx Proxy Manager: domain, forward hostname, port, Websockets, and SSL.

## Files and Locations

| Path | Purpose |
|---|---|
| `/etc/ssh/sshd_config.d/00-hardening.conf` | SSH settings managed by the script. It sorts first, so it takes priority. |
| `/etc/ssh/*.bak-<timestamp>` | Backups of the original `sshd` config files, made before the first change |
| `/etc/systemd/system/ssh.socket.d/vps-setup.conf` | Port override for `ssh.socket` (Ubuntu 24.04+) |
| `/etc/fail2ban/jail.d/sshd-local.conf` | fail2ban jail for SSH |
| `/etc/apt/sources.list.d/docker.sources` | Docker's apt repository |
| `/opt/nginx-proxy-manager/` | Nginx Proxy Manager compose file, data and certificates |
| `/opt/apps/<app>/docker-compose.yml` | Each Docker app's compose file |
| `/opt/apps/<app>/.env` | Each app's settings and secrets (mode `600`, owned by your user) |
| `/opt/apps/.vps-setup.json` | Remembers the shared Docker network between runs |

## Safety Features

- **Validate, then reload.** `sshd -t` checks the config before every reload, and `sshd -T` confirms the setting actually took effect (catching drop-in files that override it).
- **Automatic rollback.** If validation fails, the SSH config files are restored to how they were.
- **No lockouts from password changes.** Passwords are only disabled once an SSH key is installed **and** you've confirmed a key login works.
- **Root key-only check.** Choosing "key only" for root warns you if `/root/.ssh/authorized_keys` is empty.
- **Port change with revert.** The new port is opened in UFW before `sshd` moves to it. If `sshd` doesn't start listening, or you type `revert`, everything goes back to the old port. The old port is only closed after you confirm the new one works.
- **Checks on what you paste.** Public keys are checked with `ssh-keygen`, and pasting a private key is caught and refused.
- **Safe to stop.** Pressing Ctrl+C keeps anything already applied, and you can run the script again to carry on.

## After Setup

Connect using the command shown in the final summary:

```bash
ssh -p <port> youruser@your.server.ip
```

Useful commands:

```bash
sudo ss -tlnp                         # see what's listening and exposed
sudo fail2ban-client status sshd      # see fail2ban bans
sudo ufw status numbered              # list firewall rules
sudo sshd -T | grep -Ei 'port|permitroot|passwordauth'   # effective SSH settings
cd /opt/apps/<app> && sudo docker compose logs -f        # follow an app's logs
```

> **Back up** each app's `.env` file, especially `N8N_ENCRYPTION_KEY` for n8n. Without it, a restored database can't be decrypted.

If your VPS provider has its own firewall (a cloud control panel), remember to open any new SSH port or app port there as well.

## Troubleshooting

**`Permission denied (publickey)` when testing the key**
The key you're using doesn't match the one you pasted, or the file permissions on your local computer are wrong. The script prints the right `chmod` / `icacls` commands for Linux, macOS and Windows. Type `help` at the test prompt to see the latest SSH log lines from the server.

**`Connection timed out` after changing the SSH port**
A firewall is blocking the new port, usually your provider's control panel. Type `revert` at the prompt to go back to the old port.

**A step failed**
The error is shown and you can choose to continue. Fix the cause and run the script again; steps that already worked are safe to repeat.

**Nginx Proxy Manager, Coolify or Dokploy was skipped**
Ports 80 or 443 are already in use. Check what's using them with `sudo ss -tlnp`.

**Can't register in Open WebUI with sign-up closed**
Set `ENABLE_SIGNUP='true'` in `/opt/apps/open-webui/.env`, run `docker compose up -d`, register, then set it back.

## License

Released under the [MIT License](LICENSE).

Made by [techmitten](https://github.com/techmitten).
