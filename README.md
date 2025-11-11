# Ubuntu 24.04 Server Setup Script

Automated security hardening and setup script for fresh Ubuntu 24.04 servers.

## Features

✅ System updates & cleanup  
✅ Sudo user creation  
✅ SSH hardening (disable root/password auth)  
✅ Fail2Ban intrusion prevention  
✅ Docker & Docker Compose  
✅ Nginx Proxy Manager  
✅ UFW firewall configuration  

## Quick Start

```bash
# Download and run
curl -O https://raw.githubusercontent.com/username/repo/main/setup.py
sudo python3 setup.py
```

## Requirements

- Ubuntu 24.04 server
- Root access
- SSH public key
- Console access (important!)

## What Gets Configured

| Component | Details |
|-----------|---------|
| SSH | Root login disabled, key-only auth |
| Firewall | Ports 22, 80, 81, 443 open |
| Fail2Ban | 3 attempts, 1hr ban |
| Docker | Latest with compose plugin |
| NPM | Running on port 81 |

## Post-Install

**Nginx Proxy Manager:**  
- URL: `http://your-ip:81`
- Login: `admin@example.com` / `changeme`
- ⚠️ **Change password immediately**

**Test SSH before closing root session:**
```bash
ssh newuser@your-ip
```

## Configuration Files

```
/opt/nginx-proxy-manager/     # NPM + Docker Compose
/etc/ssh/sshd_config           # SSH config (backed up)
/etc/fail2ban/jail.local       # Fail2Ban rules
```

## Warning

⚠️ **This script modifies SSH settings.** Ensure you have:
- Console access to your server
- Valid SSH public key ready
- Tested new user login before closing root session

## License

MIT
