# Clavister OneConnect OIDC VPN Client for Linux

A lightweight Linux CLI and status bar helper for Clavister firewalls configured with Microsoft Entra ID (OIDC) authentication.

## Requirements

- [`openconnect`](https://www.infradead.org/openconnect/), which sets up the VPN tunnel. The tool does not install it.
- `pipx`, to install the tool (see below).

On Arch Linux / Omarchy:

```bash
sudo pacman -S openconnect python-pipx
```

On Debian / Ubuntu:

```bash
sudo apt install openconnect pipx
```

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

Gateways you connect to are remembered, most recent first. Running `connect` without an address uses the last one. Remove one with `clavister-vpn forget <address>`.

## Status bar icon

### Install

1. Install the tool with `pipx` (see [Installation](#installation)).
2. Add the icon to your bar. Run this as your normal user, without `sudo`:

   ```bash
   clavister-vpn setup-bar
   ```

On [Omarchy](https://omarchy.org/) this installs a bar widget to `~/.config/omarchy/plugins/io.github.fenomeno1991.clavister-vpn/` and puts it first on the right side of the bar. It shows up straight away; no restart needed. You can move it like any other widget, for example with `omarchy bar move io.github.fenomeno1991.clavister-vpn --section right`.

Without the Omarchy shell, `setup-bar` adds a module to your Waybar config instead (a backup is saved next to it) and restarts Waybar.

### Using it

The icon shows whether the VPN is connected, and pulses while a connection is being set up. Clicking it opens a dropdown in the style of the Wi-Fi menu, where you can:

- toggle the VPN on and off (connects to the last used gateway)
- click a remembered gateway to connect to it, or to disconnect if it's the active one
- hover a gateway and click ✕ to forget it
- type a new gateway address and press Enter to connect to it

Keyboard: `j`/`k` or arrow keys move between gateways, Enter connects, `a` jumps to the address field, Esc closes.

Connecting and disconnecting open a terminal window, so `sudo` can ask for your password and you can follow the browser login. Keep that window open while you're connected; closing it ends the VPN session.

### Keybindings

The widget can also be controlled from the command line, which makes it easy to bind to keys:

```bash
omarchy-shell io.github.fenomeno1991.clavister-vpn up                  # connect to the last used gateway
omarchy-shell io.github.fenomeno1991.clavister-vpn up vpn.example.com  # connect to a specific gateway
omarchy-shell io.github.fenomeno1991.clavister-vpn down                # disconnect
omarchy-shell io.github.fenomeno1991.clavister-vpn toggle              # open/close the dropdown
```

### Updating

Reinstall, then run `setup-bar` again. If the widget changed, it restarts the Omarchy shell so the new version loads (the shell's own hot reload keeps running the old one):

```bash
pipx install --force git+https://github.com/fenomeno1991/clavister-oidc-vpn.git
clavister-vpn setup-bar
```

### Removing

```bash
omarchy plugin remove io.github.fenomeno1991.clavister-vpn
```