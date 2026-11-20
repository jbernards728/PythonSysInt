from __future__ import annotations

import ctypes
import os
import socket
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext

import requests

from network_intel import (
    analyze_ip_or_cidr,
    batch_audit_and_export,
    get_local_lan_ip,
    lookup_geolocation_asn,
)

# Browser-inspired light palette (Chrome/Edge style)
COLORS = {
    "tab_strip": "#dee1e6",
    "tab_inactive_hover": "#e8eaed",
    "toolbar": "#ffffff",
    "border": "#dadce0",
    "omnibox_bg": "#f1f3f4",
    "omnibox_focus": "#ffffff",
    "page_bg": "#f8f9fa",
    "card_bg": "#ffffff",
    "text": "#202124",
    "muted": "#5f6368",
    "accent": "#1a73e8",
    "accent_hover": "#1557b0",
    "accent_soft": "#e8f0fe",
    "success": "#137333",
    "success_soft": "#e6f4ea",
    "warn": "#b06000",
    "warn_soft": "#fef7e0",
    "error": "#c5221f",
    "error_soft": "#fce8e6",
}


def get_public_ip() -> str:
    """Fetches this device's public external IP address with fallback."""
    endpoints = (
        ("https://api.ipify.org?format=json", "ip"),
        ("https://ipapi.co/json/", "ip"),
        ("http://ip-api.com/json/", "query"),
    )
    last_err: Exception | None = None
    for url, key in endpoints:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                ip = resp.json().get(key)
                if ip:
                    return str(ip).strip()
        except requests.RequestException as exc:
            last_err = exc
    raise requests.RequestException(f"Could not detect public IP: {last_err or 'No response'}")


class BrowserStyleNetworkGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Network Intel Browser")
        self.root.geometry("920x640")
        self.root.minsize(740, 520)
        self.root.configure(bg=COLORS["tab_strip"])

        self.lan_ip = get_local_lan_ip()
        self.active_tab = "lookup"
        self.history: list[str] = []
        self.history_index = -1
        self.last_valid_targets: list[str] = []
        self.is_busy = False

        self._build_chrome()
        self._build_pages()
        self._build_statusbar()
        self._switch_tab("lookup")
        self._render_welcome()

    # ------------------------------------------------------------------
    # Browser Chrome (Tabs + Address Bar + Bookmarks)
    # ------------------------------------------------------------------
    def _build_chrome(self) -> None:
        # 1. Tab Strip
        self.tab_strip = tk.Frame(self.root, bg=COLORS["tab_strip"], height=38)
        self.tab_strip.pack(fill=tk.X)
        self.tab_strip.pack_propagate(False)

        self.tab_buttons: dict[str, tk.Button] = {}
        tabs = [
            ("lookup", "  IP Lookup  "),
            ("device", "  My Device  "),
            ("exports", "  Exports  "),
        ]
        for key, label in tabs:
            btn = tk.Button(
                self.tab_strip,
                text=label,
                font=("Segoe UI", 9, "bold"),
                bd=0,
                relief=tk.FLAT,
                cursor="hand2",
                padx=12,
                pady=6,
                command=lambda k=key: self._switch_tab(k),
            )
            btn.pack(side=tk.LEFT, padx=(6, 0), pady=(6, 0), fill=tk.Y)
            self.tab_buttons[key] = btn

        # 2. Navigation & Omnibox Toolbar
        toolbar = tk.Frame(self.root, bg=COLORS["toolbar"], pady=8, padx=10)
        toolbar.pack(fill=tk.X)

        self.back_btn = self._nav_button(toolbar, "←", self._go_back, state=tk.DISABLED)
        self.back_btn.pack(side=tk.LEFT, padx=(0, 2))

        self.fwd_btn = self._nav_button(toolbar, "→", self._go_forward, state=tk.DISABLED)
        self.fwd_btn.pack(side=tk.LEFT, padx=(0, 2))

        self.reload_btn = self._nav_button(toolbar, "↻", self._reload_current)
        self.reload_btn.pack(side=tk.LEFT, padx=(0, 2))

        self.home_btn = self._nav_button(toolbar, "⌂", self._open_my_device)
        self.home_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Omnibox (Address Bar)
        self.omnibox_frame = tk.Frame(
            toolbar,
            bg=COLORS["omnibox_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=10,
            pady=4,
        )
        self.omnibox_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.omnibox_prefix = tk.Label(
            self.omnibox_frame,
            text="net://",
            bg=COLORS["omnibox_bg"],
            fg=COLORS["muted"],
            font=("Consolas", 10),
        )
        self.omnibox_prefix.pack(side=tk.LEFT, padx=(0, 4))

        self.address_var = tk.StringVar()
        self.address_entry = tk.Entry(
            self.omnibox_frame,
            textvariable=self.address_var,
            bg=COLORS["omnibox_bg"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            font=("Consolas", 10),
            bd=0,
            relief=tk.FLAT,
        )
        self.address_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.address_entry.bind("<Return>", lambda _e: self._on_address_submit())
        self.address_entry.bind("<FocusIn>", lambda _e: self._set_omnibox_focus(True))
        self.address_entry.bind("<FocusOut>", lambda _e: self._set_omnibox_focus(False))

        # Action buttons on right of address bar
        self.go_btn = tk.Button(
            toolbar,
            text="Go",
            bg=COLORS["accent"],
            fg="#ffffff",
            activebackground=COLORS["accent_hover"],
            activeforeground="#ffffff",
            font=("Segoe UI", 9, "bold"),
            bd=0,
            relief=tk.FLAT,
            cursor="hand2",
            padx=14,
            pady=5,
            command=self._on_address_submit,
        )
        self.go_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.export_json_btn = tk.Button(
            toolbar,
            text="JSON",
            bg=COLORS["omnibox_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 8, "bold"),
            bd=0,
            relief=tk.FLAT,
            cursor="hand2",
            padx=10,
            pady=6,
            state=tk.DISABLED,
            command=lambda: self._start_export("json"),
        )
        self.export_json_btn.pack(side=tk.LEFT, padx=(0, 4))

        self.export_csv_btn = tk.Button(
            toolbar,
            text="CSV",
            bg=COLORS["omnibox_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 8, "bold"),
            bd=0,
            relief=tk.FLAT,
            cursor="hand2",
            padx=10,
            pady=6,
            state=tk.DISABLED,
            command=lambda: self._start_export("csv"),
        )
        self.export_csv_btn.pack(side=tk.LEFT)

        # 3. Bookmarks Bar
        bookmarks = tk.Frame(self.root, bg=COLORS["toolbar"], padx=12, pady=4)
        bookmarks.pack(fill=tk.X)

        tk.Label(
            bookmarks,
            text="Bookmarks:",
            bg=COLORS["toolbar"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
        ).pack(side=tk.LEFT, padx=(0, 6))

        bookmark_items = [
            ("★ My Device", self._open_my_device),
            ("★ 8.8.8.8 (Google)", lambda: self._navigate_lookup("8.8.8.8")),
            ("★ 1.1.1.1 (Cloudflare)", lambda: self._navigate_lookup("1.1.1.1")),
            ("★ 192.168.1.0/24 (LAN)", lambda: self._navigate_lookup("192.168.1.0/24")),
            ("★ IPv6 DNS", lambda: self._navigate_lookup("2001:4860:4860::8888")),
        ]
        for label, cmd in bookmark_items:
            b = tk.Button(
                bookmarks,
                text=label,
                bg=COLORS["toolbar"],
                fg=COLORS["text"],
                activebackground=COLORS["omnibox_bg"],
                font=("Segoe UI", 8),
                bd=0,
                relief=tk.FLAT,
                cursor="hand2",
                padx=8,
                pady=2,
                command=cmd,
            )
            b.pack(side=tk.LEFT, padx=(0, 4))

        # Divider line under browser chrome
        tk.Frame(self.root, bg=COLORS["border"], height=1).pack(fill=tk.X)

    def _nav_button(
        self, parent: tk.Widget, text: str, command, state: str = tk.NORMAL
    ) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            bg=COLORS["toolbar"],
            fg=COLORS["text"],
            disabledforeground="#bdc1c6",
            activebackground=COLORS["omnibox_bg"],
            font=("Segoe UI", 11),
            bd=0,
            relief=tk.FLAT,
            cursor="hand2",
            width=3,
            state=state,
            command=command,
        )

    def _set_omnibox_focus(self, focused: bool) -> None:
        bg = COLORS["omnibox_focus"] if focused else COLORS["omnibox_bg"]
        border = COLORS["accent"] if focused else COLORS["border"]
        self.omnibox_frame.config(bg=bg, highlightbackground=border, highlightthickness=2 if focused else 1)
        self.omnibox_prefix.config(bg=bg)
        self.address_entry.config(bg=bg)

    # ------------------------------------------------------------------
    # Viewport Pages (Lookup, My Device, Exports)
    # ------------------------------------------------------------------
    def _build_pages(self) -> None:
        self.viewport = tk.Frame(self.root, bg=COLORS["page_bg"])
        self.viewport.pack(fill=tk.BOTH, expand=True)

        # Page 1: Scrollable IP Lookup Canvas
        self.lookup_page = tk.Frame(self.viewport, bg=COLORS["page_bg"])
        self.lookup_canvas = tk.Canvas(
            self.lookup_page, bg=COLORS["page_bg"], highlightthickness=0
        )
        self.lookup_scroll = tk.Scrollbar(
            self.lookup_page, orient=tk.VERTICAL, command=self.lookup_canvas.yview
        )
        self.lookup_content = tk.Frame(self.lookup_canvas, bg=COLORS["page_bg"], padx=24, pady=18)
        self.lookup_window = self.lookup_canvas.create_window(
            (0, 0), window=self.lookup_content, anchor="nw"
        )
        self.lookup_canvas.configure(yscrollcommand=self.lookup_scroll.set)
        self.lookup_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.lookup_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.lookup_content.bind(
            "<Configure>",
            lambda _e: self.lookup_canvas.configure(
                scrollregion=self.lookup_canvas.bbox("all")
            ),
        )
        self.lookup_canvas.bind(
            "<Configure>",
            lambda e: self.lookup_canvas.itemconfig(self.lookup_window, width=e.width),
        )
        self.root.bind_all("<MouseWheel>", self._on_mousewheel)

        # Page 2: My Device Page
        self.device_page = tk.Frame(self.viewport, bg=COLORS["page_bg"], padx=24, pady=18)
        self.device_canvas = tk.Canvas(
            self.device_page, bg=COLORS["page_bg"], highlightthickness=0
        )
        self.device_scroll = tk.Scrollbar(
            self.device_page, orient=tk.VERTICAL, command=self.device_canvas.yview
        )
        self.device_content = tk.Frame(self.device_canvas, bg=COLORS["page_bg"])
        self.device_window = self.device_canvas.create_window(
            (0, 0), window=self.device_content, anchor="nw"
        )
        self.device_canvas.configure(yscrollcommand=self.device_scroll.set)
        self.device_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.device_content.bind(
            "<Configure>",
            lambda _e: self.device_canvas.configure(
                scrollregion=self.device_canvas.bbox("all")
            ),
        )
        self.device_canvas.bind(
            "<Configure>",
            lambda e: self.device_canvas.itemconfig(self.device_window, width=e.width),
        )

        # Page 3: Exports Page
        self.exports_page = tk.Frame(self.viewport, bg=COLORS["page_bg"], padx=24, pady=18)
        exp_top = tk.Frame(self.exports_page, bg=COLORS["page_bg"])
        exp_top.pack(fill=tk.X, pady=(0, 10))
        tk.Label(
            exp_top,
            text="Saved Reports (exports/)",
            bg=COLORS["page_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(side=tk.LEFT)

        tk.Button(
            exp_top,
            text="Open Folder",
            bg=COLORS["accent"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._open_exports_folder,
        ).pack(side=tk.RIGHT)
        tk.Button(
            exp_top,
            text="Refresh",
            bg=COLORS["toolbar"],
            fg=COLORS["text"],
            font=("Segoe UI", 9),
            bd=1,
            relief=tk.SOLID,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._refresh_exports_list,
        ).pack(side=tk.RIGHT, padx=(0, 8))

        exp_body = tk.Frame(self.exports_page, bg=COLORS["page_bg"])
        exp_body.pack(fill=tk.BOTH, expand=True)

        list_card = tk.Frame(
            exp_body,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            width=260,
        )
        list_card.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        list_card.pack_propagate(False)

        self.exports_listbox = tk.Listbox(
            list_card,
            bg=COLORS["card_bg"],
            fg=COLORS["text"],
            selectbackground=COLORS["accent_soft"],
            selectforeground=COLORS["accent"],
            font=("Consolas", 9),
            bd=0,
            highlightthickness=0,
        )
        self.exports_listbox.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.exports_listbox.bind("<<ListboxSelect>>", self._preview_selected_export)

        preview_card = tk.Frame(
            exp_body,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        preview_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.export_preview = scrolledtext.ScrolledText(
            preview_card,
            bg=COLORS["card_bg"],
            fg=COLORS["text"],
            font=("Consolas", 9),
            bd=0,
            padx=10,
            pady=10,
            state=tk.DISABLED,
        )
        self.export_preview.pack(fill=tk.BOTH, expand=True)

        self.pages = {
            "lookup": self.lookup_page,
            "device": self.device_page,
            "exports": self.exports_page,
        }

    def _build_statusbar(self) -> None:
        tk.Frame(self.root, bg=COLORS["border"], height=1).pack(fill=tk.X)
        bar = tk.Frame(self.root, bg=COLORS["omnibox_bg"], padx=12, pady=4)
        bar.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Ready — Enter an IP or CIDR in the address bar.")
        tk.Label(
            bar,
            textvariable=self.status_var,
            bg=COLORS["omnibox_bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
        ).pack(side=tk.LEFT)

        self.lan_status_var = tk.StringVar(value=f"Local LAN IP: {self.lan_ip}")
        tk.Label(
            bar,
            textvariable=self.lan_status_var,
            bg=COLORS["omnibox_bg"],
            fg=COLORS["muted"],
            font=("Consolas", 8),
        ).pack(side=tk.RIGHT)

    def _on_mousewheel(self, event: tk.Event) -> None:
        if self.active_tab == "lookup":
            self.lookup_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        elif self.active_tab == "device":
            self.device_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # ------------------------------------------------------------------
    # Tab & Navigation Logic
    # ------------------------------------------------------------------
    def _switch_tab(self, tab_key: str) -> None:
        self.active_tab = tab_key
        for k, page in self.pages.items():
            if k == tab_key:
                page.pack(fill=tk.BOTH, expand=True)
            else:
                page.pack_forget()

        for k, btn in self.tab_buttons.items():
            if k == tab_key:
                btn.config(bg=COLORS["toolbar"], fg=COLORS["text"])
            else:
                btn.config(bg=COLORS["tab_strip"], fg=COLORS["muted"])

        if tab_key == "device":
            self.address_var.set("my-device")
            self._scan_my_device()
        elif tab_key == "exports":
            self.address_var.set("exports/")
            self._refresh_exports_list()
        elif tab_key == "lookup" and self.address_var.get() in ("my-device", "exports/"):
            self.address_var.set("")

    def _open_my_device(self) -> None:
        self._switch_tab("device")

    def _on_address_submit(self) -> None:
        raw = self.address_var.get().strip()
        if raw.lower() in ("my-device", "localhost", "me", ""):
            self._open_my_device()
            return
        if raw.lower() in ("exports", "exports/"):
            self._switch_tab("exports")
            return
        self._navigate_lookup(raw)

    def _navigate_lookup(self, query: str, record_history: bool = True) -> None:
        self.active_tab = "lookup"
        for k, page in self.pages.items():
            page.pack(fill=tk.BOTH, expand=True) if k == "lookup" else page.pack_forget()
        for k, btn in self.tab_buttons.items():
            btn.config(
                bg=COLORS["toolbar"] if k == "lookup" else COLORS["tab_strip"],
                fg=COLORS["text"] if k == "lookup" else COLORS["muted"],
            )

        self.address_var.set(query)
        if record_history:
            if self.history_index < len(self.history) - 1:
                self.history = self.history[: self.history_index + 1]
            if not self.history or self.history[-1] != query:
                self.history.append(query)
                self.history_index = len(self.history) - 1
            self._update_nav_buttons()

        targets = [t.strip() for t in query.replace(" ", ",").split(",") if t.strip()]
        if targets:
            self._start_lookup(targets)

    def _go_back(self) -> None:
        if self.history_index > 0:
            self.history_index -= 1
            self._update_nav_buttons()
            self._navigate_lookup(self.history[self.history_index], record_history=False)

    def _go_forward(self) -> None:
        if self.history_index < len(self.history) - 1:
            self.history_index += 1
            self._update_nav_buttons()
            self._navigate_lookup(self.history[self.history_index], record_history=False)

    def _reload_current(self) -> None:
        if self.active_tab == "device":
            self._scan_my_device()
        elif self.active_tab == "exports":
            self._refresh_exports_list()
        else:
            raw = self.address_var.get().strip()
            if raw:
                self._navigate_lookup(raw, record_history=False)
            else:
                self._render_welcome()

    def _update_nav_buttons(self) -> None:
        self.back_btn.config(state=tk.NORMAL if self.history_index > 0 else tk.DISABLED)
        self.fwd_btn.config(
            state=tk.NORMAL if self.history_index < len(self.history) - 1 else tk.DISABLED
        )

    # ------------------------------------------------------------------
    # Rendering Helpers (Web-style Cards & Badges)
    # ------------------------------------------------------------------
    def _clear_frame(self, frame: tk.Frame) -> None:
        for child in frame.winfo_children():
            child.destroy()

    def _make_badge(self, parent: tk.Widget, text: str, fg: str, bg: str) -> tk.Label:
        return tk.Label(
            parent,
            text=text,
            fg=fg,
            bg=bg,
            font=("Segoe UI", 8, "bold"),
            padx=8,
            pady=2,
        )

    def _render_welcome(self) -> None:
        self._clear_frame(self.lookup_content)
        card = tk.Frame(
            self.lookup_content,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
            padx=28,
            pady=28,
        )
        card.pack(fill=tk.X, pady=(16, 0))

        tk.Label(
            card,
            text="Network Intelligence",
            bg=COLORS["card_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor=tk.W)

        tk.Label(
            card,
            text="Type an IPv4/IPv6 address or CIDR block in the address bar above (comma-separated for multiple), or click a quick action below.",
            bg=COLORS["card_bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10),
            wraplength=680,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(6, 18))

        btn_row = tk.Frame(card, bg=COLORS["card_bg"])
        btn_row.pack(anchor=tk.W)

        tk.Button(
            btn_row,
            text="Scan My Device (Local + Public IP)",
            bg=COLORS["accent"],
            fg="#ffffff",
            activebackground=COLORS["accent_hover"],
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
            bd=0,
            padx=16,
            pady=8,
            cursor="hand2",
            command=self._open_my_device,
        ).pack(side=tk.LEFT, padx=(0, 10))

        tk.Button(
            btn_row,
            text="Try 8.8.8.8, 192.168.1.0/24",
            bg=COLORS["omnibox_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 9, "bold"),
            bd=0,
            padx=14,
            pady=9,
            cursor="hand2",
            command=lambda: self._navigate_lookup("8.8.8.8, 192.168.1.0/24"),
        ).pack(side=tk.LEFT)

    def _render_result_card(
        self, parent: tk.Frame, title: str, info: dict | None = None, error: str | None = None
    ) -> None:
        card = tk.Frame(
            parent,
            bg=COLORS["card_bg"],
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        card.pack(fill=tk.X, pady=(0, 12))

        header = tk.Frame(card, bg=COLORS["card_bg"], padx=16, pady=10)
        header.pack(fill=tk.X)

        tk.Label(
            header,
            text=title,
            bg=COLORS["card_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 11, "bold"),
        ).pack(side=tk.LEFT)

        if error:
            self._make_badge(header, "Error", COLORS["error"], COLORS["error_soft"]).pack(
                side=tk.RIGHT
            )
            tk.Frame(card, bg=COLORS["border"], height=1).pack(fill=tk.X)
            tk.Label(
                card,
                text=error,
                bg=COLORS["card_bg"],
                fg=COLORS["error"],
                font=("Consolas", 9),
                padx=16,
                pady=12,
                anchor=tk.W,
            ).pack(fill=tk.X)
            return

        if not info:
            return

        # Badges
        if info.get("is_private"):
            self._make_badge(header, "Private", COLORS["warn"], COLORS["warn_soft"]).pack(
                side=tk.RIGHT, padx=(6, 0)
            )
        else:
            self._make_badge(header, "Public", COLORS["success"], COLORS["success_soft"]).pack(
                side=tk.RIGHT, padx=(6, 0)
            )

        if info.get("version"):
            self._make_badge(
                header, info["version"], COLORS["accent"], COLORS["accent_soft"]
            ).pack(side=tk.RIGHT)

        tk.Frame(card, bg=COLORS["border"], height=1).pack(fill=tk.X)

        grid = tk.Frame(card, bg=COLORS["card_bg"], padx=16, pady=12)
        grid.pack(fill=tk.X)
        grid.columnconfigure(1, weight=1)
        grid.columnconfigure(3, weight=1)

        items = [
            (k.replace("_", " ").title(), str(v))
            for k, v in info.items()
            if k not in ("input", "version")
        ]
        for idx, (label, value) in enumerate(items):
            row = idx // 2
            col_offset = (idx % 2) * 2
            tk.Label(
                grid,
                text=f"{label}:",
                bg=COLORS["card_bg"],
                fg=COLORS["muted"],
                font=("Segoe UI", 9),
                anchor=tk.W,
            ).grid(row=row, column=col_offset, sticky=tk.W, padx=(0, 8), pady=3)
            tk.Label(
                grid,
                text=value,
                bg=COLORS["card_bg"],
                fg=COLORS["text"],
                font=("Consolas", 9),
                anchor=tk.W,
            ).grid(row=row, column=col_offset + 1, sticky=tk.W, padx=(0, 20), pady=3)

    # ------------------------------------------------------------------
    # Lookup Worker
    # ------------------------------------------------------------------
    def _set_busy(self, busy: bool) -> None:
        self.is_busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.go_btn.config(state=state)
        self.reload_btn.config(state=state)
        export_state = tk.NORMAL if (not busy and self.last_valid_targets) else tk.DISABLED
        self.export_json_btn.config(state=export_state)
        self.export_csv_btn.config(state=export_state)

    def _start_lookup(self, targets: list[str]) -> None:
        if self.is_busy:
            return
        self._set_busy(True)
        self._clear_frame(self.lookup_content)
        self.status_var.set(f"Loading {len(targets)} target(s)...")

        tk.Label(
            self.lookup_content,
            text=f"Analyzing {', '.join(targets)}...",
            bg=COLORS["page_bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor=tk.W, pady=12)

        threading.Thread(target=self._run_lookup, args=(targets,), daemon=True).start()

    def _run_lookup(self, targets: list[str]) -> None:
        results: list[tuple[str, dict | None, str | None]] = []
        valid_targets: list[str] = []

        for target in targets:
            try:
                info = analyze_ip_or_cidr(target)
                if not info["is_private"] and "/" not in target:
                    try:
                        geo = lookup_geolocation_asn(target)
                        info.update(geo)
                    except requests.RequestException as exc:
                        info["geolocation_error"] = str(exc)
                valid_targets.append(info["input"])
                results.append((target, info, None))
            except ValueError as exc:
                results.append((target, None, str(exc)))

        self.root.after(0, self._finish_lookup, results, valid_targets)

    def _finish_lookup(
        self,
        results: list[tuple[str, dict | None, str | None]],
        valid_targets: list[str],
    ) -> None:
        self._clear_frame(self.lookup_content)
        for target, info, error in results:
            self._render_result_card(self.lookup_content, target, info=info, error=error)

        self.last_valid_targets = valid_targets
        self._set_busy(False)
        self.status_var.set(f"Done — {len(valid_targets)} of {len(results)} target(s) analyzed.")

    # ------------------------------------------------------------------
    # My Device Scanner (Local LAN + Hostname + Public IP/Geo/ASN)
    # ------------------------------------------------------------------
    def _scan_my_device(self) -> None:
        if self.is_busy:
            return
        self._set_busy(True)
        self._clear_frame(self.device_content)
        self.status_var.set("Scanning your device (Local LAN + Public IP)...")

        tk.Label(
            self.device_content,
            text="Scanning your device...",
            bg=COLORS["page_bg"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor=tk.W, pady=12)

        threading.Thread(target=self._run_device_scan, daemon=True).start()

    def _run_device_scan(self) -> None:
        hostname = socket.gethostname()
        lan_ip = get_local_lan_ip()
        lan_info = analyze_ip_or_cidr(lan_ip)
        lan_info["hostname"] = hostname

        pub_info: dict | None = None
        pub_error: str | None = None
        pub_ip: str | None = None
        try:
            pub_ip = get_public_ip()
            pub_info = analyze_ip_or_cidr(pub_ip)
            try:
                pub_info.update(lookup_geolocation_asn(pub_ip))
            except requests.RequestException as exc:
                pub_info["geolocation_error"] = str(exc)
        except Exception as exc:
            pub_error = str(exc)

        self.root.after(
            0, self._finish_device_scan, lan_ip, lan_info, pub_ip, pub_info, pub_error
        )

    def _finish_device_scan(
        self,
        lan_ip: str,
        lan_info: dict,
        pub_ip: str | None,
        pub_info: dict | None,
        pub_error: str | None,
    ) -> None:
        self.lan_ip = lan_ip
        self.lan_status_var.set(f"Local LAN IP: {lan_ip}")
        self._clear_frame(self.device_content)

        top = tk.Frame(self.device_content, bg=COLORS["page_bg"])
        top.pack(fill=tk.X, pady=(0, 12))
        tk.Label(
            top,
            text="My Device Network Overview",
            bg=COLORS["page_bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 13, "bold"),
        ).pack(side=tk.LEFT)
        tk.Button(
            top,
            text="Rescan Device",
            bg=COLORS["accent"],
            fg="#ffffff",
            font=("Segoe UI", 9, "bold"),
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=self._scan_my_device,
        ).pack(side=tk.RIGHT)

        self._render_result_card(
            self.device_content, f"Local Network Interface — {lan_ip}", info=lan_info
        )

        if pub_info and pub_ip:
            self._render_result_card(
                self.device_content, f"Public Internet IP — {pub_ip}", info=pub_info
            )
            self.last_valid_targets = [lan_ip, pub_ip]
        else:
            self._render_result_card(
                self.device_content,
                "Public Internet IP",
                error=pub_error or "Unable to detect public IP.",
            )
            self.last_valid_targets = [lan_ip]

        self._set_busy(False)
        self.status_var.set("Device scan complete. Use JSON or CSV in the toolbar to export.")

    # ------------------------------------------------------------------
    # Export & Exports Viewer
    # ------------------------------------------------------------------
    def _start_export(self, fmt: str) -> None:
        if not self.last_valid_targets or self.is_busy:
            return
        self._set_busy(True)
        self.status_var.set(f"Exporting {fmt.upper()} report...")
        threading.Thread(
            target=self._run_export,
            args=(list(self.last_valid_targets), fmt),
            daemon=True,
        ).start()

    def _run_export(self, targets: list[str], fmt: str) -> None:
        try:
            os.makedirs("exports", exist_ok=True)
            timestamp = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            out_base = os.path.join("exports", f"{timestamp}-{self.lan_ip}-ip-lookup")
            saved_path = batch_audit_and_export(targets, export_format=fmt, filename=out_base)
            self.root.after(0, self._finish_export, saved_path, None)
        except Exception as exc:
            self.root.after(0, self._finish_export, None, str(exc))

    def _finish_export(self, saved_path: str | None, error: str | None) -> None:
        self._set_busy(False)
        if error:
            self.status_var.set("Export failed.")
            messagebox.showerror("Export Failed", error)
        else:
            self.status_var.set(f"Exported to {saved_path}")
            messagebox.showinfo("Export Saved", f"Report exported to:\n{saved_path}")

    def _refresh_exports_list(self) -> None:
        os.makedirs("exports", exist_ok=True)
        files = sorted(
            [f for f in os.listdir("exports") if os.path.isfile(os.path.join("exports", f))],
            reverse=True,
        )
        self.exports_listbox.delete(0, tk.END)
        for name in files:
            self.exports_listbox.insert(tk.END, name)

        self.export_preview.config(state=tk.NORMAL)
        self.export_preview.delete("1.0", tk.END)
        if files:
            self.export_preview.insert(tk.END, "Select a file on the left to preview its contents.")
        else:
            self.export_preview.insert(tk.END, "No exported reports yet.")
        self.export_preview.config(state=tk.DISABLED)
        self.status_var.set(f"Showing {len(files)} exported file(s).")

    def _preview_selected_export(self, _event: tk.Event) -> None:
        selection = self.exports_listbox.curselection()
        if not selection:
            return
        filename = self.exports_listbox.get(selection[0])
        filepath = os.path.join("exports", filename)
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except OSError as exc:
            content = f"Error reading file: {exc}"

        self.export_preview.config(state=tk.NORMAL)
        self.export_preview.delete("1.0", tk.END)
        self.export_preview.insert(tk.END, content)
        self.export_preview.config(state=tk.DISABLED)

    def _open_exports_folder(self) -> None:
        exports_dir = os.path.abspath("exports")
        os.makedirs(exports_dir, exist_ok=True)
        try:
            os.startfile(exports_dir)
        except AttributeError:
            messagebox.showinfo("Exports Folder", f"Reports are saved in:\n{exports_dir}")


def main() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    BrowserStyleNetworkGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
