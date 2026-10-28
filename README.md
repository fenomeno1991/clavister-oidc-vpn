# Clavister OneConnect OIDC VPN Client for Linux

A lightweight Linux CLI and status bar helper for Clavister firewalls configured with Microsoft Entra ID (OIDC) authentication.

## Installation

Install directly via `pipx`:

```bash
pipx install git+https://github.com/fenomeno1991/clavister-oidc-vpn.git
```
## Connect to VPN

Running the tool requires `sudo -E` because it binds to local port 80 to capture the Entra ID OAuth callback and initiates the `openconnect` network tunnel (the -E flag preserves your user session environment so your web browser can open for login).

Because sudo uses a restricted search path (secure_path), choose one of the two methods below to run it:

### Option 1: Direct Path (No extra setup)

Run directly using the binary location installed by `pipx`:

```bash
sudo -E ~/.local/bin/clavister-vpn connect oneconnect.org.com
```

### Option 2: Symlink (Recommended for shorthand usage)

Create a symlink to `/usr/local/bin` once:

```bash
sudo ln -sf ~/.local/bin/clavister-vpn /usr/local/bin/clavister-vpn
```

Then connect from anywhere with:

```bash
sudo -E clavister-vpn connect oneconnect.org.com
```