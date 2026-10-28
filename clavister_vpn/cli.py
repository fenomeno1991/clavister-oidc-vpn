#!/usr/bin/env python3
import argparse
import base64
import filecmp
import hashlib
import http.server
import json
import os
import pwd
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import requests

def user_home():
    # Under sudo, keep config in the invoking user's home so the bar can read it
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")

CONFIG_DIR = os.path.join(user_home(), ".config", "clavister-vpn")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
USER_AGENT = "Clavister OneConnect VPN"
REDIRECT_URI = "http://127.0.0.1/oneconnect/oauth/"
OMARCHY_SHELL_CONFIG = os.path.expanduser("~/.config/omarchy/shell.json")
OMARCHY_PLUGIN_ID = "io.github.fenomeno1991.clavister-vpn"
OMARCHY_PLUGIN_SRC = os.path.join(os.path.dirname(__file__), "omarchy")
MAX_SERVERS = 10
SERVER_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:\d{1,5})?$")

auth_code = None

class OAuthCallbackHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global auth_code
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "code" in params:
            auth_code = params["code"][0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h2>Entra ID Auth Successful! Return to your terminal.</h2>")
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            err = params.get("error_description", ["Unknown error"])[0]
            self.wfile.write(f"<h2>Auth failed: {err}</h2>".encode("utf-8"))

    def log_message(self, format, *args):
        pass

def check_dependencies():
    missing = []
    if not shutil.which("openconnect"):
        missing.append("openconnect")
    if not shutil.which("xdg-open"):
        missing.append("xdg-open")
    if missing:
        print(f"[-] Error: Missing required system dependencies: {', '.join(missing)}")
        print("    Please install them via your package manager (e.g., sudo pacman -S openconnect)")
        sys.exit(1)

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def save_config(data):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    cfg = load_config()
    cfg.update(data)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)
    # Written as root under sudo: hand it back so the user (and the bar) can update it
    if os.geteuid() == 0 and os.environ.get("SUDO_UID"):
        uid, gid = int(os.environ["SUDO_UID"]), int(os.environ.get("SUDO_GID", os.environ["SUDO_UID"]))
        for path in (CONFIG_DIR, CONFIG_FILE):
            os.chown(path, uid, gid)

def known_servers(cfg):
    servers = list(cfg.get("servers", []))
    last = cfg.get("last_server")
    if last and last not in servers:
        servers.insert(0, last)
    return servers

def validate_server(server):
    server = server.strip()
    if server.startswith("https://"):
        server = server[len("https://"):]
    server = server.rstrip("/")
    if not SERVER_RE.match(server):
        print(f"[-] Error: '{server}' is not a valid gateway address.")
        sys.exit(1)
    return server

def remember_server(server):
    # Most recently used first, so the last one is always on top
    servers = [s for s in known_servers(load_config()) if s != server]
    save_config({"last_server": server, "servers": [server] + servers[:MAX_SERVERS - 1]})

def get_server(args_server):
    if args_server:
        server = validate_server(args_server)
        remember_server(server)
        return server
    cfg = load_config()
    if "last_server" in cfg:
        return cfg["last_server"]
    # Default prompt if nothing found
    server = input("Enter Clavister VPN Gateway (e.g. oneconnect.org.com): ").strip()
    if not server:
        print("[-] Error: Gateway address is required.")
        sys.exit(1)
    server = validate_server(server)
    remember_server(server)
    return server

def open_browser(url):
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            uid = subprocess.check_output(["id", "-u", sudo_user]).decode().strip()
            env = os.environ.copy()
            env["XDG_RUNTIME_DIR"] = f"/run/user/{uid}"
            subprocess.Popen(["sudo", "-u", sudo_user, "-E", "xdg-open", url], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        except Exception:
            pass
    subprocess.Popen(["xdg-open", url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def extract_cookie(session, resp):
    for k, v in session.cookies.get_dict().items():
        if k.lower() in ("webvpn", "svpncookie"):
            return f"{k}={v}"
    if "webvpn" in resp.headers.get("Set-Cookie", ""):
        return resp.headers["Set-Cookie"].split(";")[0]
    if "<?xml" in resp.text or "<config-auth" in resp.text:
        try:
            root = ET.fromstring(resp.text)
            for tag in ("session-token", "cookie", "webvpn"):
                el = root.find(f".//{tag}")
                if el is not None and el.text:
                    return el.text.strip()
        except Exception:
            pass
    return None

def cmd_connect(server_arg):
    check_dependencies()
    server = get_server(server_arg)
    vpn_url = f"https://{server}"

    # Switching gateways: only one tunnel at a time
    if is_connected():
        print(f"[*] Closing the current VPN session ({active_server() or 'unknown gateway'})...")
        cmd_disconnect()

    try:
        server_listener = http.server.HTTPServer(("127.0.0.1", 80), OAuthCallbackHandler)
    except PermissionError:
        print("[-] Error: Binding to port 80 requires root privileges. Please run with sudo -E.")
        sys.exit(1)

    session = requests.Session()
    session.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "X-Transcend-Version": "1",
        "X-Aggregate-Auth": "1",
        "X-Support-HTTP-Auth": "true",
        "Content-Type": "application/xml; charset=utf-8",
    })

    init_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<config-auth client="vpn" type="init" aggregate-auth-version="2">'
        '<version who="vpn">v9.21</version>'
        '<device-id>linux-64</device-id>'
        f'<group-access>{vpn_url}/</group-access>'
        '</config-auth>'
    )
    print(f"[*] Requesting OIDC parameters & session nonce from {server}...")
    try:
        r = session.post(f"{vpn_url}/", data=init_xml)
        root = ET.fromstring(r.text)
        discovery_url = root.find(".//discovery-endpoint").text.strip()
        client_id = root.find(".//client-id").text.strip()
        nonce = root.find(".//nonce").text.strip()
    except Exception as e:
        print(f"[-] Failed to parse OIDC configuration from gateway: {e}")
        sys.exit(1)

    print(f"[+] Got session Nonce successfully.")
    oidc_cfg = requests.get(discovery_url).json()
    authorize_endpoint = oidc_cfg["authorization_endpoint"]
    token_endpoint = oidc_cfg["token_endpoint"]

    code_verifier = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(hashed).decode("ascii").rstrip("=")

    auth_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "response_mode": "query",
        "scope": "openid profile email",
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    auth_url = f"{authorize_endpoint}?" + urllib.parse.urlencode(auth_params)
    print(f"\n[*] Opening browser for Microsoft Entra ID authentication...")
    open_browser(auth_url)

    global auth_code
    print("[*] Waiting for authentication callback on http://127.0.0.1/oneconnect/oauth/ ...")
    while auth_code is None:
        server_listener.handle_request()
    server_listener.server_close()

    print("[*] Exchanging authorization code for Entra ID Token...")
    token_resp = requests.post(token_endpoint, data={
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    })
    if not token_resp.ok:
        print(f"[-] Token exchange failed: {token_resp.text}")
        sys.exit(1)

    id_token = token_resp.json().get("id_token")
    print("[+] Acquired signed ID Token with matching Clavister nonce!")

    payload = f'<?xml version="1.0" encoding="UTF-8"?><config-auth client="vpn" type="auth-reply"><version who="vpn">v9.21</version><device-id>linux-64</device-id><auth><id-token>{id_token}</id-token><token>{id_token}</token><oidc-token>{id_token}</oidc-token><password>{id_token}</password></auth></config-auth>'
    session.headers["Authorization"] = f"Bearer {id_token}"

    cookie = None
    for endpoint in ["/auth", "/"]:
        resp = session.post(f"{vpn_url}{endpoint}", data=payload)
        cookie = extract_cookie(session, resp)
        if cookie:
            break

    if not cookie:
        print("[-] Authentication failed: Could not retrieve session cookie from gateway.")
        sys.exit(1)

    raw_token = cookie.split("=", 1)[1] if cookie.startswith("webvpn=") else cookie
    formatted_cookie = f"webvpn={raw_token}"
    print(f"[+] VPN session established. Launching OpenConnect tunnel...")

    proc = subprocess.Popen(
        [
            "openconnect",
            "--protocol=anyconnect",
            f"--useragent={USER_AGENT}",
            "--cookie-on-stdin",
            vpn_url,
        ],
        stdin=subprocess.PIPE,
    )
    proc.communicate(input=f"{formatted_cookie}\n".encode())

def cmd_disconnect():
    print("[*] Terminating active OpenConnect sessions...")
    result = subprocess.run(["sudo", "pkill", "-f", "openconnect"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[+] VPN disconnected.")

def is_connected():
    return subprocess.run(["pgrep", "-x", "openconnect"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def active_server():
    # cmd_connect passes the gateway as https://<server> on openconnect's command line
    out = subprocess.run(["pgrep", "-ax", "openconnect"], capture_output=True, text=True).stdout
    for arg in out.split():
        if arg.startswith("https://"):
            return arg[len("https://"):].rstrip("/")
    return None

def is_connecting():
    # Covers the sudo prompt and the browser login, before openconnect starts
    return subprocess.run(["pgrep", "-f", "clavister-vpn connect"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

def cmd_status(waybar=False, as_json=False):
    connected = is_connected()
    if as_json:
        cfg = load_config()
        state = "connected" if connected else ("connecting" if is_connecting() else "disconnected")
        print(json.dumps({
            "state": state,
            "server": active_server() if connected else None,
            "last_server": cfg.get("last_server"),
            "servers": known_servers(cfg),
        }))
        return
    if waybar:
        if connected:
            # "active" highlights the module in the Omarchy shell bar
            out = {"text": " 󰌋 VPN", "tooltip": "Clavister VPN: Connected", "class": ["connected", "active"]}
        else:
            out = {"text": " 󰌆 ", "tooltip": "Clavister VPN: Disconnected", "class": "disconnected"}
        print(json.dumps(out))
    else:
        if connected:
            print("[+] Status: Connected (tun0 active)")
        else:
            print("[-] Status: Disconnected")

def run_in_terminal(command):
    for term in ("xdg-terminal-exec", "foot", "alacritty", "kitty", "ghostty"):
        if shutil.which(term):
            break
    else:
        subprocess.Popen(["notify-send", "Clavister VPN", "No terminal emulator found."])
        return
    flag = "-e" if term in ("alacritty", "ghostty") else None
    argv = [term] + ([flag] if flag else []) + ["bash", "-c", command]
    subprocess.Popen(argv, start_new_session=True)

def own_exe():
    # sudo's secure_path won't include ~/.local/bin, so pass an absolute path
    return shutil.which("clavister-vpn") or "/usr/local/bin/clavister-vpn"

def connect_in_terminal(server=None):
    # Launched from the bar there is no tty for sudo to prompt on, so run in a terminal
    cmd = f"sudo -E {shlex.quote(own_exe())} connect"
    if server:
        cmd += " " + shlex.quote(validate_server(server))
    run_in_terminal(cmd)

def disconnect_in_terminal():
    run_in_terminal(f"sudo {shlex.quote(own_exe())} disconnect; sleep 2")

def cmd_forget(server):
    cfg = load_config()
    servers = [s for s in known_servers(cfg) if s != server]
    data = {"servers": servers}
    if cfg.get("last_server") == server:
        data["last_server"] = servers[0] if servers else None
    save_config(data)
    print(f"[+] Forgot {server}.")

def cmd_menu():
    connected = is_connected()
    menu_options = "Disconnect VPN\nView Status" if connected else "Connect VPN"
    
    # Check for available dmenu-compatible launchers
    if shutil.which("walker"):
        cmd = ["walker", "--dmenu"]
    elif shutil.which("rofi"):
        cmd = ["rofi", "-dmenu", "-p", "Clavister VPN"]
    elif shutil.which("wofi"):
        cmd = ["wofi", "--dmenu", "--prompt", "Clavister VPN"]
    elif shutil.which("fuzzel"):
        cmd = ["fuzzel", "--dmenu"]
    else:
        print("[-] No supported launcher found (walker, rofi, wofi, fuzzel).")
        return

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    choice, _ = proc.communicate(input=menu_options)
    choice = choice.strip()

    if choice == "Connect VPN":
        connect_in_terminal()
    elif choice == "Disconnect VPN":
        disconnect_in_terminal()
    elif choice == "View Status":
        subprocess.Popen(["notify-send", "Clavister VPN", "VPN is currently connected and active."])


def cmd_setup_waybar():
    config_path = os.path.expanduser("~/.config/waybar/config.jsonc")
    if not os.path.exists(config_path):
        config_path = os.path.expanduser("~/.config/waybar/config")
        if not os.path.exists(config_path):
            print("[-] Could not find Waybar configuration file.")
            return

    with open(config_path, "r") as f:
        content = f.read()

    if '"custom/clavister-vpn"' in content:
        print("[*] Waybar config already contains the VPN module. Skipping.")
        return

    # Create a backup
    backup_path = config_path + ".backup"
    shutil.copy(config_path, backup_path)
    print(f"[*] Created backup of Waybar config at {backup_path}")

    # Inject into modules-right
    content = re.sub(
        r'("modules-right"\s*:\s*\[)', 
        r'\1\n        "custom/clavister-vpn",', 
        content, 
        count=1
    )

    # Append module definition before the final closing brace
    module_def = """    ,
    "custom/clavister-vpn": {
        "exec": "clavister-vpn status --waybar",
        "return-type": "json",
        "interval": 3,
        "format": "{}",
        "on-click": "clavister-vpn menu"
    }
    """
    last_brace = content.rfind('}')
    if last_brace != -1:
        content = content[:last_brace] + module_def + content[last_brace:]
        
        with open(config_path, "w") as f:
            f.write(content)
        print("[+] Successfully injected Waybar module.")
        
        print("[*] Restarting Waybar to apply changes...")
        subprocess.run(["killall", "waybar"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.Popen(["waybar"], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        print("[-] Failed to parse config file structure.")

def cmd_setup_omarchy():
    plugin_dir = os.path.expanduser(f"~/.config/omarchy/plugins/{OMARCHY_PLUGIN_ID}")
    names = [n for n in os.listdir(OMARCHY_PLUGIN_SRC) if n != "__pycache__"]
    existed = os.path.isdir(plugin_dir)
    changed = existed and filecmp.cmpfiles(OMARCHY_PLUGIN_SRC, plugin_dir, names, shallow=False)[0] != names
    shutil.copytree(OMARCHY_PLUGIN_SRC, plugin_dir, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__"))
    print(f"[+] Installed Omarchy bar plugin to {plugin_dir}")
    if changed:
        # The shell's hot reload reuses its cached compiled QML, so an update needs a restart
        print("[*] Restarting the Omarchy shell to load the updated widget...")
        subprocess.run(["omarchy", "restart", "shell"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    with open(OMARCHY_SHELL_CONFIG, "r") as f:
        cfg = json.load(f)
    layout = cfg.get("bar", {}).get("layout", {})
    placed = any(m.get("id") == OMARCHY_PLUGIN_ID for section in layout.values() for m in section)

    # Drop the command module older versions of setup-bar added
    old = [s for s in layout.values() if any(m.get("id") == "clavister-vpn" for m in s)]
    if old:
        backup_path = OMARCHY_SHELL_CONFIG + ".backup"
        shutil.copy(OMARCHY_SHELL_CONFIG, backup_path)
        print(f"[*] Created backup of Omarchy shell config at {backup_path}")
        for section in old:
            section[:] = [m for m in section if m.get("id") != "clavister-vpn"]
        with open(OMARCHY_SHELL_CONFIG, "w") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("[*] Removed the old VPN command module from the bar.")

    if placed:
        print("[*] VPN widget is already on the bar.")
        return

    subprocess.run(["omarchy-shell", "shell", "rescanPlugins"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    result = subprocess.run(["omarchy", "plugin", "enable", OMARCHY_PLUGIN_ID, "--section", "right", "--index", "0"])
    if result.returncode == 0:
        print("[+] Added the VPN widget to the Omarchy bar.")
    else:
        print(f"[-] Could not enable the plugin. Try: omarchy plugin enable {OMARCHY_PLUGIN_ID}")

def cmd_setup_bar():
    if os.path.exists(OMARCHY_SHELL_CONFIG):
        cmd_setup_omarchy()
    else:
        cmd_setup_waybar()

def main():
    parser = argparse.ArgumentParser(description="Clavister OneConnect OIDC VPN Client for Linux")
    subparsers = parser.add_subparsers(dest="command")

    connect_parser = subparsers.add_parser("connect", help="Connect to VPN")
    connect_parser.add_argument("server", nargs="?", help="VPN Gateway hostname")
    connect_parser.add_argument("--terminal", action="store_true", help="Run in a new terminal window (for bar/menu use)")

    disconnect_parser = subparsers.add_parser("disconnect", help="Disconnect VPN")
    disconnect_parser.add_argument("--terminal", action="store_true", help="Run in a new terminal window (for bar/menu use)")

    forget_parser = subparsers.add_parser("forget", help="Remove a remembered gateway")
    forget_parser.add_argument("server", help="VPN Gateway hostname")

    status_parser = subparsers.add_parser("status", help="Show connection status")
    status_parser.add_argument("--waybar", action="store_true", help="Output Waybar JSON format")
    status_parser.add_argument("--json", action="store_true", help="Output state and remembered gateways as JSON")

    subparsers.add_parser("menu", help="Launch GUI action menu (rofi/wofi)")

    subparsers.add_parser("setup-bar", help="Add the VPN status icon to the Omarchy bar (or Waybar)")
    subparsers.add_parser("setup-waybar", help="Automatically inject Waybar configuration")

    args = parser.parse_args()

    if args.command == "connect":
        if args.terminal:
            connect_in_terminal(args.server)
        else:
            cmd_connect(args.server)
    elif args.command == "disconnect":
        if args.terminal:
            disconnect_in_terminal()
        else:
            cmd_disconnect()
    elif args.command == "forget":
        cmd_forget(args.server)
    elif args.command == "status":
        cmd_status(args.waybar, args.json)
    elif args.command == "menu":
        cmd_menu()
    elif args.command == "setup-bar":
        cmd_setup_bar()
    elif args.command == "setup-waybar":
        cmd_setup_waybar()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()