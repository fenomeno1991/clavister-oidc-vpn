#!/usr/bin/env python3
import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import shutil
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET
import requests

CONFIG_DIR = os.path.expanduser("~/.config/clavister-vpn")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
USER_AGENT = "Clavister OneConnect VPN"
REDIRECT_URI = "http://127.0.0.1/oneconnect/oauth/"

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

def get_server(args_server):
    if args_server:
        save_config({"last_server": args_server})
        return args_server
    cfg = load_config()
    if "last_server" in cfg:
        return cfg["last_server"]
    # Default prompt if nothing found
    server = input("Enter Clavister VPN Gateway (e.g. oc.exitsolution.se): ").strip()
    if not server:
        print("[-] Error: Gateway address is required.")
        sys.exit(1)
    save_config({"last_server": server})
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

def cmd_status(waybar=False):
    connected = is_connected()
    if waybar:
        if connected:
            out = {"text": " 󰌋 VPN", "tooltip": "Clavister VPN: Connected", "class": "connected"}
        else:
            out = {"text": " 󰌆 ", "tooltip": "Clavister VPN: Disconnected", "class": "disconnected"}
        print(json.dumps(out))
    else:
        if connected:
            print("[+] Status: Connected (tun0 active)")
        else:
            print("[-] Status: Disconnected")

def cmd_menu():
    connected = is_connected()
    menu_options = "Disconnect VPN\nView Status" if connected else "Connect VPN"
    
    # Check for rofi or wofi
    launcher = "rofi" if shutil.which("rofi") else ("wofi" if shutil.which("wofi") else None)
    if not launcher:
        print("[-] Neither rofi nor wofi found for GUI menu.")
        return

    if launcher == "rofi":
        cmd = ["rofi", "-dmenu", "-p", "Clavister VPN"]
    else:
        cmd = ["wofi", "--dmenu", "--prompt", "Clavister VPN"]

    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    choice, _ = proc.communicate(input=menu_options)
    choice = choice.strip()

    if choice == "Connect VPN":
        subprocess.Popen(["sudo", "-E", sys.argv[0], "connect"])
    elif choice == "Disconnect VPN":
        subprocess.Popen(["sudo", sys.argv[0], "disconnect"])
    elif choice == "View Status":
        subprocess.Popen(["notify-send", "Clavister VPN", "VPN is currently connected and active."])

def main():
    parser = argparse.ArgumentParser(description="Clavister OneConnect OIDC VPN Client for Linux")
    subparsers = parser.add_subparsers(dest="command")

    connect_parser = subparsers.add_parser("connect", help="Connect to VPN")
    connect_parser.add_argument("server", nargs="?", help="VPN Gateway hostname")

    subparsers.add_parser("disconnect", help="Disconnect VPN")
    
    status_parser = subparsers.add_parser("status", help="Show connection status")
    status_parser.add_argument("--waybar", action="store_true", help="Output Waybar JSON format")

    subparsers.add_parser("menu", help="Launch GUI action menu (rofi/wofi)")

    args = parser.parse_args()

    if args.command == "connect":
        cmd_connect(args.server)
    elif args.command == "disconnect":
        cmd_disconnect()
    elif args.command == "status":
        cmd_status(args.waybar)
    elif args.command == "menu":
        cmd_menu()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()