"""
Session Hijacking vs Token Validation Defense - Cyber Range Simulation
Topic: Session Hijacking Attack vs Token Validation Defense Mechanism
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import random
import hashlib
import hmac
import base64
import json
import datetime
import uuid

# ─────────────────────────────────────────────────────────────
#  Colour Palette
# ─────────────────────────────────────────────────────────────
C = {
    "bg":        "#0d1117",
    "panel":     "#161b22",
    "border":    "#30363d",
    "accent":    "#58a6ff",
    "green":     "#3fb950",
    "red":       "#f85149",
    "yellow":    "#d29922",
    "purple":    "#bc8cff",
    "orange":    "#ff9f43",
    "text":      "#e6edf3",
    "muted":     "#8b949e",
    "btn_blue":  "#1f6feb",
    "btn_red":   "#b91c1c",
    "btn_green": "#1a7f37",
    "danger_bg": "#2a0f0f",
    "success_bg":"#0f2a1b",
}

# ─────────────────────────────────────────────────────────────
#  Session / Token Logic
# ─────────────────────────────────────────────────────────────

SECRET_KEY = "super_secret_server_key_2024"

USERS = [
    {"username": "alice",   "email": "alice@example.com",   "role": "admin"},
    {"username": "bob",     "email": "bob@example.com",     "role": "user"},
    {"username": "charlie", "email": "charlie@example.com", "role": "moderator"},
]

ATTACK_METHODS = [
    "XSS Cookie Theft",
    "Network Sniffing",
    "Predictable Token",
    "Cross-Site Request Forgery",
    "Man-in-the-Middle",
]

# Global state
active_sessions = {}   # token -> session_data
attack_log      = []
stats = {
    "attempts": 0,
    "success":  0,
    "blocked":  0,
    "hijacked_accounts": [],
}


def reset_all():
    global active_sessions, attack_log, stats
    active_sessions.clear()
    attack_log.clear()
    stats = {"attempts": 0, "success": 0, "blocked": 0, "hijacked_accounts": []}


# ── Token generation ─────────────────────────────────────────

def generate_weak_token(username):
    """Predictable token — easy to forge."""
    raw = f"{username}:{int(time.time() // 1000)}"
    return base64.b64encode(raw.encode()).decode()


def generate_strong_token(username, ip="192.168.1.10"):
    """Signed token with expiry + IP binding."""
    payload = {
        "username": username,
        "ip":       ip,
        "exp":      time.time() + 1800,   # 30 min
        "jti":      str(uuid.uuid4()),    # unique ID
        "iat":      time.time(),
    }
    payload_b64 = base64.b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}", payload


def create_session(username, defense_level, client_ip="192.168.1.10"):
    """Create a session and store it."""
    if defense_level == "none":
        token = generate_weak_token(username)
        session = {
            "username":  username,
            "token":     token,
            "ip":        client_ip,
            "created":   time.time(),
            "exp":       time.time() + 86400,  # 24 hours (too long)
            "signed":    False,
            "ip_bound":  False,
            "rotated":   False,
        }
    else:
        token, payload = generate_strong_token(username, client_ip)
        session = {
            "username":  username,
            "token":     token,
            "ip":        payload["ip"],
            "created":   time.time(),
            "exp":       payload["exp"],
            "jti":       payload["jti"],
            "signed":    True,
            "ip_bound":  defense_level in ("ip_binding", "full"),
            "rotated":   defense_level == "full",
        }
    active_sessions[token] = session
    return token, session


def attempt_hijack(target_user, stolen_token, attacker_ip, defense_level, defenses):
    """
    Try to use a stolen token.
    Returns: (success, reason, detail)
    """
    stats["attempts"] += 1

    session = active_sessions.get(stolen_token)
    if not session:
        stats["blocked"] += 1
        return False, "BLOCKED", "Token not found in active sessions"

    # Defense 1: Signature verification
    if defenses["signature"] and session["signed"]:
        # Attacker cannot forge the signature
        if stolen_token != session["token"]:
            stats["blocked"] += 1
            return False, "BLOCKED", "Signature mismatch — token tampered"

    # Defense 2: Token expiry
    if defenses["expiry"]:
        if time.time() > session["exp"]:
            del active_sessions[stolen_token]
            stats["blocked"] += 1
            return False, "BLOCKED", "Token expired — session invalidated"

    # Defense 3: IP binding
    if defenses["ip_binding"] and session["ip_bound"]:
        if attacker_ip != session["ip"]:
            stats["blocked"] += 1
            return False, "BLOCKED", f"IP mismatch — token bound to {session['ip']}, request from {attacker_ip}"

    # Defense 4: Token rotation (used token is invalidated)
    if defenses["rotation"] and session["rotated"]:
        # Simulate: legitimate user already used this token once, new token issued
        if random.random() < 0.7:
            del active_sessions[stolen_token]
            stats["blocked"] += 1
            return False, "BLOCKED", "Token already rotated — stolen token is stale"

    # All defenses passed (or disabled) — attack succeeds
    stats["success"] += 1
    if session["username"] not in stats["hijacked_accounts"]:
        stats["hijacked_accounts"].append(session["username"])
    return True, "HIJACKED", f"Session hijacked as user: {session['username']}"


# ─────────────────────────────────────────────────────────────
#  GUI Application
# ─────────────────────────────────────────────────────────────

class SessionHijackApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🔐 Session Hijacking vs Token Validation Defense — Cyber Range")
        self.geometry("1280x830")
        self.minsize(1100, 700)
        self.configure(bg=C["bg"])
        self._setup_styles()
        self._build_ui()
        self._init_sessions()

    def _setup_styles(self):
        s = ttk.Style(self)
        s.theme_use("default")
        s.configure("TFrame",      background=C["bg"])
        s.configure("Panel.TFrame",background=C["panel"])
        s.configure("TLabel",      background=C["bg"],    foreground=C["text"],   font=("Consolas", 10))
        s.configure("TCheckbutton",background=C["panel"], foreground=C["text"],   font=("Consolas", 10),
                    selectcolor=C["btn_blue"])
        s.map("TCheckbutton", background=[("active", C["panel"])])
        s.configure("TCombobox",   font=("Consolas", 10), fieldbackground=C["border"],
                    background=C["border"], foreground=C["text"])
        s.configure("TNotebook",   background=C["bg"])
        s.configure("TNotebook.Tab", background=C["panel"], foreground=C["muted"],
                    font=("Consolas", 10), padding=[10, 4])
        s.map("TNotebook.Tab",
              background=[("selected", C["bg"])],
              foreground=[("selected", C["accent"])])

    # ── Layout ───────────────────────────────────────────────
    def _build_ui(self):
        # Header
        hdr = tk.Frame(self, bg=C["panel"], height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="  🍪  Session Hijacking vs Token Validation Defense  —  Cyber Range",
                 bg=C["panel"], fg=C["accent"], font=("Consolas", 13, "bold")).pack(side="left", padx=16, pady=12)
        tk.Label(hdr, text="Attack-Defense Simulation  |  Web Security Lab",
                 bg=C["panel"], fg=C["muted"], font=("Consolas", 9)).pack(side="right", padx=20)
        tk.Frame(self, bg=C["border"], height=1).pack(fill="x")

        body = tk.Frame(self, bg=C["bg"])
        body.pack(fill="both", expand=True, padx=10, pady=8)

        # Left panel
        left = tk.Frame(body, bg=C["panel"], width=330)
        left.pack(side="left", fill="y", padx=(0, 8))
        left.pack_propagate(False)
        self._build_left(left)

        # Right notebook
        right = tk.Frame(body, bg=C["bg"])
        right.pack(side="left", fill="both", expand=True)
        self._build_right(right)

    def _build_left(self, p):
        def lbl(text, fg=C["muted"], font=("Consolas", 9)):
            return tk.Label(p, text=text, bg=C["panel"], fg=fg, font=font)

        lbl("ATTACK CONFIGURATION", C["accent"], ("Consolas", 10, "bold")).pack(anchor="w", padx=14, pady=(14, 2))
        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=14, pady=2)

        # Target user
        lbl("Target User:").pack(anchor="w", padx=14, pady=(6, 2))
        self.user_var = tk.StringVar(value=USERS[0]["username"])
        ttk.Combobox(p, textvariable=self.user_var,
                     values=[u["username"] for u in USERS],
                     state="readonly", width=28).pack(anchor="w", padx=14, pady=2)

        # Attack method
        lbl("Attack Method:").pack(anchor="w", padx=14, pady=(8, 2))
        self.method_var = tk.StringVar(value=ATTACK_METHODS[0])
        ttk.Combobox(p, textvariable=self.method_var,
                     values=ATTACK_METHODS,
                     state="readonly", width=28).pack(anchor="w", padx=14, pady=2)

        # Attacker IP
        lbl("Attacker IP:").pack(anchor="w", padx=14, pady=(8, 2))
        self.attacker_ip_var = tk.StringVar(value="10.0.0.99")
        tk.Entry(p, textvariable=self.attacker_ip_var, bg=C["border"], fg=C["text"],
                 font=("Consolas", 10), insertbackground=C["text"], width=22,
                 relief="flat").pack(anchor="w", padx=14, pady=2)

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=14, pady=8)

        # Defense toggles
        lbl("DEFENSE SETTINGS", C["accent"], ("Consolas", 10, "bold")).pack(anchor="w", padx=14, pady=(2, 4))

        self.def_sig      = tk.BooleanVar(value=True)
        self.def_expiry   = tk.BooleanVar(value=True)
        self.def_ip       = tk.BooleanVar(value=False)
        self.def_rotation = tk.BooleanVar(value=False)

        defenses = [
            (self.def_sig,      "✓ Token Signature (HMAC)"),
            (self.def_expiry,   "✓ Token Expiry Check"),
            (self.def_ip,       "✓ IP Address Binding"),
            (self.def_rotation, "✓ Token Rotation"),
        ]
        for var, text in defenses:
            tk.Checkbutton(p, text=f"  {text}", variable=var,
                           bg=C["panel"], fg=C["text"], selectcolor=C["btn_blue"],
                           activebackground=C["panel"],
                           font=("Consolas", 10)).pack(anchor="w", padx=14, pady=1)

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=14, pady=8)

        # Speed & Burst
        lbl("Simulation Speed:").pack(anchor="w", padx=14)
        self.speed_var = tk.DoubleVar(value=0.7)
        tk.Scale(p, from_=0.1, to=2.0, resolution=0.1, orient="horizontal",
                 variable=self.speed_var, bg=C["panel"], fg=C["text"],
                 troughcolor=C["border"], highlightthickness=0,
                 activebackground=C["btn_blue"], length=210,
                 font=("Consolas", 8)).pack(anchor="w", padx=14)

        lbl("Burst Count:").pack(anchor="w", padx=14, pady=(6, 0))
        self.burst_var = tk.IntVar(value=4)
        tk.Scale(p, from_=1, to=15, orient="horizontal",
                 variable=self.burst_var, bg=C["panel"], fg=C["text"],
                 troughcolor=C["border"], highlightthickness=0,
                 activebackground=C["btn_blue"], length=210,
                 font=("Consolas", 8)).pack(anchor="w", padx=14)

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=14, pady=8)

        # Buttons
        btn = {"font": ("Consolas", 10, "bold"), "bd": 0, "relief": "flat",
               "cursor": "hand2", "pady": 7}

        tk.Button(p, text="▶  HIJACK SESSION",
                  bg=C["btn_red"], fg="white",
                  command=self._single_attack, **btn).pack(fill="x", padx=14, pady=3)
        tk.Button(p, text="⚡  BURST ATTACK",
                  bg="#7d2222", fg="white",
                  command=self._burst_attack, **btn).pack(fill="x", padx=14, pady=3)
        tk.Button(p, text="🔄  CREATE NEW SESSIONS",
                  bg=C["btn_green"], fg="white",
                  command=self._init_sessions, **btn).pack(fill="x", padx=14, pady=3)
        tk.Button(p, text="🗑  RESET SIMULATION",
                  bg=C["border"], fg=C["text"],
                  command=self._reset, **btn).pack(fill="x", padx=14, pady=3)

        # Active sessions display
        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=14, pady=6)
        lbl("ACTIVE SESSIONS:", C["accent"], ("Consolas", 9, "bold")).pack(anchor="w", padx=14)
        self.session_text = tk.Text(p, bg=C["bg"], fg=C["green"],
                                     font=("Consolas", 8), height=7, bd=0,
                                     insertbackground=C["text"], state="disabled")
        self.session_text.pack(fill="x", padx=14, pady=4)

    def _build_right(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)
        self.nb = nb

        sim_tab   = tk.Frame(nb, bg=C["bg"])
        token_tab = tk.Frame(nb, bg=C["bg"])
        stats_tab = tk.Frame(nb, bg=C["bg"])
        theory_tab= tk.Frame(nb, bg=C["bg"])

        nb.add(sim_tab,    text="  📡 Live Simulation  ")
        nb.add(token_tab,  text="  🔍 Token Inspector  ")
        nb.add(stats_tab,  text="  📊 Statistics  ")
        nb.add(theory_tab, text="  📚 How It Works  ")

        self._build_sim_tab(sim_tab)
        self._build_token_tab(token_tab)
        self._build_stats_tab(stats_tab)
        self._build_theory_tab(theory_tab)

    # ── Simulation Tab ───────────────────────────────────────
    def _build_sim_tab(self, p):
        top = tk.Frame(p, bg=C["panel"], height=36)
        top.pack(fill="x")
        top.pack_propagate(False)
        self.status_dot = tk.Label(top, text="●", bg=C["panel"],
                                    fg=C["green"], font=("Consolas", 14))
        self.status_dot.pack(side="left", padx=10, pady=8)
        self.status_lbl = tk.Label(top, text="Ready — create sessions and launch attack",
                                    bg=C["panel"], fg=C["muted"], font=("Consolas", 9))
        self.status_lbl.pack(side="left")

        # Flow diagram
        diag = tk.Frame(p, bg=C["bg"], height=120)
        diag.pack(fill="x", padx=8, pady=6)
        diag.pack_propagate(False)
        self.net_canvas = tk.Canvas(diag, bg=C["bg"], highlightthickness=0, height=120)
        self.net_canvas.pack(fill="both", expand=True)
        self.net_canvas.bind("<Configure>", lambda e: self._draw_flow())
        self._draw_flow()

        # Log
        tk.Label(p, text="▼  ATTACK LOG", bg=C["bg"],
                 fg=C["accent"], font=("Consolas", 10, "bold")).pack(anchor="w", padx=8)

        self.log_text = scrolledtext.ScrolledText(
            p, bg=C["panel"], fg=C["text"],
            font=("Consolas", 10), bd=0, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=(2, 8))
        self.log_text.tag_config("success", foreground=C["red"])
        self.log_text.tag_config("blocked", foreground=C["green"])
        self.log_text.tag_config("warn",    foreground=C["yellow"])
        self.log_text.tag_config("info",    foreground=C["accent"])
        self.log_text.tag_config("header",  foreground=C["purple"])
        self.log_text.tag_config("cred",    foreground=C["orange"], background="#1a0f00")
        self.log_text.tag_config("muted",   foreground=C["muted"])

    def _draw_flow(self):
        c = self.net_canvas
        c.delete("all")
        w = c.winfo_width() or 860
        h = 120
        cy = h // 2

        nodes = [
            (w * 0.09,  cy, "👤", "Victim\nUser",         C["accent"]),
            (w * 0.30,  cy, "🍪", "Session\nToken",       C["yellow"]),
            (w * 0.55,  cy, "☠",  "Attacker",             C["red"]),
            (w * 0.78,  cy, "🌐", "Web\nServer",          C["green"]),
            (w * 0.96,  cy, "🛡", "Token\nValidator",     C["purple"]),
        ]
        for x, y, icon, label, col in nodes:
            c.create_oval(x-24, y-24, x+24, y+24, fill=C["panel"], outline=col, width=2)
            c.create_text(x, y-6,  text=icon,  fill=col, font=("", 13))
            c.create_text(x, y+18, text=label, fill=col, font=("Consolas", 7), justify="center")

        arrow = {"arrow": tk.LAST, "width": 2}
        # Victim -> Token
        c.create_line(w*0.09+26, cy, w*0.30-26, cy, fill=C["yellow"],   **arrow)
        c.create_text((w*0.09+w*0.30)/2, cy-14, text="login", fill=C["yellow"], font=("Consolas", 7))
        # Token -> Attacker
        c.create_line(w*0.30+26, cy, w*0.55-26, cy, fill=C["red"], dash=(5,3), **arrow)
        c.create_text((w*0.30+w*0.55)/2, cy-14, text="stolen!", fill=C["red"], font=("Consolas", 7))
        # Attacker -> Server
        c.create_line(w*0.55+26, cy, w*0.78-26, cy, fill=C["orange"], **arrow)
        c.create_text((w*0.55+w*0.78)/2, cy-14, text="replay token", fill=C["orange"], font=("Consolas", 7))
        # Server -> Validator
        c.create_line(w*0.78+26, cy, w*0.96-26, cy, fill=C["purple"], dash=(4,4), **arrow)
        c.create_text((w*0.78+w*0.96)/2, cy+20, text="validate", fill=C["purple"], font=("Consolas", 7))

    # ── Token Inspector Tab ──────────────────────────────────
    def _build_token_tab(self, p):
        tk.Label(p, text="TOKEN INSPECTOR", bg=C["bg"],
                 fg=C["accent"], font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 2))

        pane = tk.PanedWindow(p, orient="horizontal", bg=C["bg"], sashwidth=6, bd=0)
        pane.pack(fill="both", expand=True, padx=8, pady=4)

        left = tk.Frame(pane, bg=C["panel"])
        pane.add(left, minsize=200)
        tk.Label(left, text="  Weak Token (No Defense)", bg=C["panel"],
                 fg=C["red"], font=("Consolas", 10, "bold")).pack(anchor="w", pady=4)
        self.weak_token_text = scrolledtext.ScrolledText(
            left, bg="#1a0a0a", fg="#f78166",
            font=("Consolas", 10), bd=0, state="disabled", wrap="word")
        self.weak_token_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        right = tk.Frame(pane, bg=C["panel"])
        pane.add(right, minsize=200)
        tk.Label(right, text="  Strong Token (With Defense)", bg=C["panel"],
                 fg=C["green"], font=("Consolas", 10, "bold")).pack(anchor="w", pady=4)
        self.strong_token_text = scrolledtext.ScrolledText(
            right, bg="#0a1a0a", fg="#7ee787",
            font=("Consolas", 10), bd=0, state="disabled", wrap="word")
        self.strong_token_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        self._update_token_display()

    # ── Stats Tab ────────────────────────────────────────────
    def _build_stats_tab(self, p):
        tk.Label(p, text="SIMULATION STATISTICS", bg=C["bg"],
                 fg=C["accent"], font=("Consolas", 11, "bold")).pack(anchor="w", padx=10, pady=(8, 4))

        row = tk.Frame(p, bg=C["bg"])
        row.pack(fill="x", padx=8, pady=4)

        self.stat_cards = {}
        for key, label, col in [
            ("attempts",  "Total Attempts",    C["accent"]),
            ("success",   "Hijacks Succeeded", C["red"]),
            ("blocked",   "Attacks Blocked",   C["green"]),
            ("hijacked",  "Accounts Hijacked", C["orange"]),
        ]:
            card = tk.Frame(row, bg=C["panel"], padx=14, pady=10)
            card.pack(side="left", fill="both", expand=True, padx=4)
            v = tk.Label(card, text="0", bg=C["panel"], fg=col, font=("Consolas", 28, "bold"))
            v.pack()
            tk.Label(card, text=label, bg=C["panel"], fg=C["muted"], font=("Consolas", 9)).pack()
            self.stat_cards[key] = v

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=10, pady=6)

        tk.Label(p, text="DEFENSE EFFECTIVENESS", bg=C["bg"],
                 fg=C["muted"], font=("Consolas", 9, "bold")).pack(anchor="w", padx=10)
        self.bar_canvas = tk.Canvas(p, bg=C["panel"], height=150, highlightthickness=0)
        self.bar_canvas.pack(fill="x", padx=10, pady=4)
        self.bar_canvas.bind("<Configure>", lambda e: self._draw_bar_chart())

        tk.Frame(p, bg=C["border"], height=1).pack(fill="x", padx=10, pady=4)
        tk.Label(p, text="⚠  HIJACKED ACCOUNTS", bg=C["bg"],
                 fg=C["red"], font=("Consolas", 10, "bold")).pack(anchor="w", padx=10)
        self.hijack_text = scrolledtext.ScrolledText(
            p, bg=C["danger_bg"], fg=C["orange"],
            font=("Consolas", 10), bd=0, state="disabled", height=5, wrap="word")
        self.hijack_text.pack(fill="x", padx=10, pady=4)

    # ── Theory Tab ───────────────────────────────────────────
    def _build_theory_tab(self, p):
        text = scrolledtext.ScrolledText(
            p, bg=C["panel"], fg=C["text"],
            font=("Consolas", 10), bd=0, wrap="word", state="disabled",
            padx=16, pady=12)
        text.pack(fill="both", expand=True, padx=8, pady=8)
        text.tag_config("h1",   foreground=C["accent"],  font=("Consolas", 13, "bold"))
        text.tag_config("h2",   foreground=C["purple"],  font=("Consolas", 11, "bold"))
        text.tag_config("code", foreground=C["green"],   background=C["bg"], font=("Consolas", 10))
        text.tag_config("warn", foreground=C["yellow"])
        text.tag_config("muted",foreground=C["muted"])

        text.config(state="normal")
        sections = [
            ("h1",  "Session Hijacking vs Token Validation Defense\n\n"),
            ("h2",  "What is a Session Token?\n"),
            ("",    """When you log into a website, the server creates a session and gives
your browser a unique token (like a temporary ID card). Every request
you make after login carries this token so the server knows who you are.
It is usually stored in a browser Cookie or as a JWT (JSON Web Token).\n\n"""),
            ("h2",  "What is Session Hijacking?\n"),
            ("",    """Session Hijacking is when an attacker steals your session token
and uses it to impersonate you — without knowing your password.\n\n"""),
            ("code","""  Attack Methods:
  1. XSS (Cross-Site Scripting)  — malicious JS steals document.cookie
  2. Network Sniffing            — intercept token over unencrypted HTTP
  3. Predictable Tokens          — guess weak tokens (user1_123456)
  4. CSRF                        — trick browser into sending token
  5. Man-in-the-Middle           — intercept token in transit\n\n"""),
            ("h2",  "Token Validation Defenses\n"),
            ("warn","""  ✓ HMAC Signature   — server signs token; forgery is impossible
  ✓ Token Expiry     — short-lived tokens limit damage window
  ✓ IP Binding       — token only works from the original IP
  ✓ Token Rotation   — new token issued every request; stolen = stale\n\n"""),
            ("h2",  "What is a JWT?\n"),
            ("",    """JSON Web Token (JWT) has three parts:
  Header.Payload.Signature\n\n"""),
            ("code","""  Header:   {"alg": "HS256", "typ": "JWT"}
  Payload:  {"username": "alice", "exp": 1700000000, "ip": "..."}
  Signature: HMAC-SHA256(header + payload, SECRET_KEY)\n\n"""),
            ("",    """If an attacker modifies the payload (e.g. changes username to "admin"),
the signature will NOT match and the server rejects the token.\n\n"""),
            ("h2",  "Defense Comparison\n"),
            ("code","""  Weak Token:   dXNlcjE6MTcwMA==   (base64 of "user1:1700")
                        → predictable, forgeable, never expires

  Strong Token: eyJ1c2VybmFtZSI6ImFsaWNlIi4uLn0=.HMAC_SIGNATURE
                        → signed, expires in 30 min, IP-bound\n\n"""),
            ("muted","  References: OWASP Session Management, RFC 7519 (JWT)\n"),
        ]
        for tag, txt in sections:
            text.insert("end", txt, tag if tag else "")
        text.config(state="disabled")

    # ── Helpers ──────────────────────────────────────────────
    def _init_sessions(self):
        active_sessions.clear()
        defense = "full" if (self.def_sig.get() or self.def_ip.get()) else "none"
        for u in USERS:
            create_session(u["username"], defense)
        self._log(f"✓ Created {len(USERS)} sessions for: {', '.join(u['username'] for u in USERS)}\n", "blocked")
        self._refresh_sessions_display()
        self._update_token_display()

    def _single_attack(self):
        threading.Thread(target=self._run_attack, args=(1,), daemon=True).start()

    def _burst_attack(self):
        threading.Thread(target=self._run_attack, args=(self.burst_var.get(),), daemon=True).start()

    def _run_attack(self, count):
        self.status_dot.config(fg=C["red"])
        self.status_lbl.config(text="⚡ Attack in progress...")

        target   = self.user_var.get()
        method   = self.method_var.get()
        att_ip   = self.attacker_ip_var.get()
        defenses = {
            "signature": self.def_sig.get(),
            "expiry":    self.def_expiry.get(),
            "ip_binding":self.def_ip.get(),
            "rotation":  self.def_rotation.get(),
        }

        # Find token for target user
        token = next((t for t, s in active_sessions.items() if s["username"] == target), None)

        for i in range(count):
            self._log(f"\n{'─'*58}\n", "muted")
            self._log(f"[{i+1}/{count}]  ATTACK → {target}  via: {method}\n", "header")

            if not token:
                self._log("  No active session found for this user. Create sessions first.\n", "warn")
                break

            self._log(f"  Stolen token: {token[:40]}...\n", "info")
            self._log(f"  Attacker IP:  {att_ip}\n", "info")
            time.sleep(self.speed_var.get() * 0.5)

            success, result, reason = attempt_hijack(
                target, token, att_ip, "full", defenses
            )

            tag = "success" if success else "blocked"
            self._log(f"  RESULT: {result} — {reason}\n", tag)

            if success:
                user = next((u for u in USERS if u["username"] == target), {})
                msg = (f"  💀 ACCOUNT HIJACKED\n"
                       f"     Username : {target}\n"
                       f"     Email    : {user.get('email', 'N/A')}\n"
                       f"     Role     : {user.get('role', 'N/A')}\n")
                self._log(msg, "cred")
                self._append_hijack(target, user)

            self._update_stats_display()
            self._refresh_sessions_display()
            time.sleep(self.speed_var.get())

        self.status_dot.config(fg=C["green"])
        self.status_lbl.config(text=f"Last run: {count} attempt(s) completed")

    def _reset(self):
        reset_all()
        self._log_clear()
        self._refresh_sessions_display()
        self._update_stats_display()
        self.hijack_text.config(state="normal")
        self.hijack_text.delete("1.0", "end")
        self.hijack_text.config(state="disabled")
        self.status_lbl.config(text="Simulation reset — ready")
        self.status_dot.config(fg=C["green"])

    def _log(self, msg, tag=""):
        self.log_text.config(state="normal")
        self.log_text.insert("end", msg, tag if tag else "")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    def _log_clear(self):
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

    def _refresh_sessions_display(self):
        self.session_text.config(state="normal")
        self.session_text.delete("1.0", "end")
        if not active_sessions:
            self.session_text.insert("end", "  (no active sessions)")
        else:
            for token, s in active_sessions.items():
                exp_in = max(0, int(s["exp"] - time.time()))
                signed = "✓ signed" if s["signed"] else "✗ unsigned"
                self.session_text.insert(
                    "end",
                    f"  {s['username']}: {token[:18]}...\n"
                    f"    {signed}  exp:{exp_in}s\n"
                )
        self.session_text.config(state="disabled")

    def _update_token_display(self):
        # Weak token example
        weak = generate_weak_token("alice")
        weak_info = (
            f"Token:\n  {weak}\n\n"
            f"Decoded:\n  alice:{int(time.time()//1000)}\n\n"
            f"Problems:\n"
            f"  ✗ Predictable pattern\n"
            f"  ✗ No signature — forgeable\n"
            f"  ✗ No expiry — valid forever\n"
            f"  ✗ No IP binding\n"
            f"  ✗ Attacker can guess/modify\n"
        )
        self.weak_token_text.config(state="normal")
        self.weak_token_text.delete("1.0", "end")
        self.weak_token_text.insert("end", weak_info)
        self.weak_token_text.config(state="disabled")

        # Strong token example
        strong_token, payload = generate_strong_token("alice")
        parts = strong_token.split(".")
        strong_info = (
            f"Token (JWT-style):\n  {parts[0][:30]}...\n  .{parts[1][:20]}...\n\n"
            f"Payload:\n"
            f"  username : {payload['username']}\n"
            f"  ip       : {payload['ip']}\n"
            f"  exp      : {int(payload['exp'])} (30 min)\n"
            f"  jti      : {payload['jti'][:16]}...\n\n"
            f"Defenses:\n"
            f"  ✓ HMAC-SHA256 signature\n"
            f"  ✓ Expires in 30 minutes\n"
            f"  ✓ Bound to client IP\n"
            f"  ✓ Unique token ID (jti)\n"
            f"  ✓ Modification = invalid\n"
        )
        self.strong_token_text.config(state="normal")
        self.strong_token_text.delete("1.0", "end")
        self.strong_token_text.insert("end", strong_info)
        self.strong_token_text.config(state="disabled")

    def _append_hijack(self, username, user):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.hijack_text.config(state="normal")
        self.hijack_text.insert(
            "end",
            f"[{ts}]  {username}  |  {user.get('email','?')}  |  role: {user.get('role','?')}\n"
        )
        self.hijack_text.see("end")
        self.hijack_text.config(state="disabled")

    def _update_stats_display(self):
        s = stats
        self.stat_cards["attempts"].config(text=str(s["attempts"]))
        self.stat_cards["success"].config(text=str(s["success"]))
        self.stat_cards["blocked"].config(text=str(s["blocked"]))
        self.stat_cards["hijacked"].config(text=str(len(s["hijacked_accounts"])))
        self._draw_bar_chart()

    def _draw_bar_chart(self):
        c = self.bar_canvas
        c.delete("all")
        cw = c.winfo_width() or 600
        ch = 150
        s  = stats
        data = [
            ("Succeeded",  s["success"],              C["red"]),
            ("Blocked",    s["blocked"],               C["green"]),
            ("Hijacked",   len(s["hijacked_accounts"]), C["orange"]),
        ]
        total  = max(s["attempts"], 1)
        bar_w  = 70
        gap    = (cw - len(data) * bar_w) // (len(data) + 1)
        max_h  = ch - 40
        for i, (label, val, col) in enumerate(data):
            x    = gap + i * (bar_w + gap)
            bh   = int((val / total) * max_h)
            y0   = ch - 24
            y1   = y0 - bh
            c.create_rectangle(x, 20, x + bar_w, y0, fill=C["border"], outline="")
            if bh > 0:
                c.create_rectangle(x, y1, x + bar_w, y0, fill=col, outline="")
            c.create_text(x + bar_w//2, ch - 10, text=label,
                          fill=C["muted"], font=("Consolas", 8), anchor="s")
            c.create_text(x + bar_w//2, max(y1 - 6, 14), text=str(val),
                          fill=col, font=("Consolas", 10, "bold"))


# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = SessionHijackApp()
    app.mainloop()
