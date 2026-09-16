import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from datetime import datetime, timezone
import threading
import hashlib
import uuid
import asyncio
import json
import os
import urllib.error
import urllib.request

from analyzer import analyze_pcap, search_threat_hunt


CASE_FILE_TYPE = "ai-pcap-security-analyzer-case"
CASE_FORMAT_VERSION = 2
SUPPORTED_CASE_FORMAT_VERSIONS = {1, 2}
APP_VERSION = "1.5-development"
OLLAMA_API_URL = "http://127.0.0.1:11434/api/chat"
DEFAULT_OLLAMA_MODEL = "qwen3:4b-instruct"


class PCAPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI PCAP Security Analyzer")
        self.root.geometry("1100x760")
        self.root.minsize(950, 680)

        self.selected_file = None
        self.report_data = None
        self.analysis_running = False
        self.txt_report_path = None
        self.json_report_path = None
        self.csv_report_path = None
        self.current_case_path = None
        self.current_case_metadata = None

        self.generate_ai_var = tk.BooleanVar(value=False)
        self.save_reports_var = tk.BooleanVar(value=False)
        self.ai_provider_var = tk.StringVar(value="Local Ollama")
        self.ollama_model_var = tk.StringVar(value=DEFAULT_OLLAMA_MODEL)
        self.ollama_test_status_var = tk.StringVar(value="Local AI not tested yet")

        self.setup_styles()
        self.build_interface()

    def setup_styles(self):
        self.root.configure(bg="#111827")

        style = ttk.Style()

        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(
            "Main.TFrame",
            background="#111827"
        )

        style.configure(
            "Card.TFrame",
            background="#1f2937"
        )

        style.configure(
            "Card.TLabelframe",
            background="#1f2937",
            foreground="#f9fafb",
            bordercolor="#374151",
            relief="solid"
        )

        style.configure(
            "Card.TLabelframe.Label",
            background="#1f2937",
            foreground="#d1d5db",
            font=("Segoe UI", 10, "bold")
        )

        style.configure(
            "Title.TLabel",
            background="#111827",
            foreground="#f9fafb",
            font=("Segoe UI", 24, "bold")
        )

        style.configure(
            "Subtitle.TLabel",
            background="#111827",
            foreground="#9ca3af",
            font=("Segoe UI", 11)
        )

        style.configure(
            "CardTitle.TLabel",
            background="#1f2937",
            foreground="#9ca3af",
            font=("Segoe UI", 10)
        )

        style.configure(
            "CardValue.TLabel",
            background="#1f2937",
            foreground="#f9fafb",
            font=("Segoe UI", 19, "bold")
        )

        style.configure(
            "Body.TLabel",
            background="#1f2937",
            foreground="#e5e7eb",
            font=("Segoe UI", 10)
        )

        style.configure(
            "Status.TLabel",
            background="#111827",
            foreground="#d1d5db",
            font=("Segoe UI", 10)
        )

        style.configure(
            "Muted.TLabel",
            background="#111827",
            foreground="#9ca3af",
            font=("Segoe UI", 9)
        )

        style.configure(
            "CardMuted.TLabel",
            background="#1f2937",
            foreground="#9ca3af",
            font=("Segoe UI", 9)
        )

        style.configure(
            "Option.TCheckbutton",
            background="#111827",
            foreground="#d1d5db",
            font=("Segoe UI", 10)
        )

        style.map(
            "Option.TCheckbutton",
            background=[
                ("active", "#111827"),
                ("!active", "#111827")
            ],
            foreground=[
                ("disabled", "#6b7280"),
                ("!disabled", "#d1d5db")
            ]
        )

        style.configure(
            "Green.Horizontal.TProgressbar",
            troughcolor="#1f2937",
            background="#22c55e",
            bordercolor="#374151",
            lightcolor="#22c55e",
            darkcolor="#22c55e"
        )

        style.configure(
            "Primary.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(14, 8)
        )

        style.configure(
            "Secondary.TButton",
            font=("Segoe UI", 10),
            padding=(12, 7)
        )

        style.configure(
            "Treeview",
            background="#0f172a",
            fieldbackground="#0f172a",
            foreground="#d1d5db",
            rowheight=24,
            borderwidth=0,
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            background="#1f2937",
            foreground="#f9fafb",
            relief="flat",
            font=("Segoe UI", 9, "bold")
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#374151")
            ],
            foreground=[
                ("selected", "#ffffff")
            ]
        )

        style.configure(
            "TNotebook",
            background="#111827",
            borderwidth=0
        )

        style.configure(
            "TNotebook.Tab",
            font=("Segoe UI", 10),
            padding=(12, 8)
        )

        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", "#374151"),
                ("!selected", "#1f2937")
            ],
            foreground=[
                ("selected", "#ffffff"),
                ("!selected", "#d1d5db")
            ]
        )

    def build_interface(self):
        outer_frame = ttk.Frame(
            self.root,
            style="Main.TFrame"
        )
        outer_frame.pack(fill="both", expand=True)

        self.main_canvas = tk.Canvas(
            outer_frame,
            bg="#111827",
            highlightthickness=0,
            borderwidth=0
        )
        self.main_canvas.pack(
            side="left",
            fill="both",
            expand=True
        )

        self.main_scrollbar = ttk.Scrollbar(
            outer_frame,
            orient="vertical",
            command=self.main_canvas.yview
        )
        self.main_scrollbar.pack(
            side="right",
            fill="y"
        )

        self.main_canvas.configure(
            yscrollcommand=self.main_scrollbar.set
        )

        main_frame = ttk.Frame(
            self.main_canvas,
            style="Main.TFrame",
            padding=20
        )

        self.main_window = self.main_canvas.create_window(
            (0, 0),
            window=main_frame,
            anchor="nw"
        )

        main_frame.bind(
            "<Configure>",
            self.update_main_scrollregion
        )

        self.main_canvas.bind(
            "<Configure>",
            self.resize_main_content
        )

        self.bind_mousewheel(self.main_canvas)

        header_frame = ttk.Frame(
            main_frame,
            style="Main.TFrame"
        )
        header_frame.pack(fill="x", pady=(0, 18))

        title = ttk.Label(
            header_frame,
            text="AI PCAP Security Analyzer",
            style="Title.TLabel"
        )
        title.pack(anchor="w")

        subtitle = ttk.Label(
            header_frame,
            text="Defensive network traffic analysis for PCAP files",
            style="Subtitle.TLabel"
        )
        subtitle.pack(anchor="w", pady=(3, 0))

        version_label = ttk.Label(
            header_frame,
            text="GUI v1.5 Development",
            style="Muted.TLabel"
        )
        version_label.pack(anchor="w", pady=(5, 0))

        file_card = ttk.LabelFrame(
            main_frame,
            text="PCAP File",
            style="Card.TLabelframe",
            padding=12
        )
        file_card.pack(fill="x", pady=(0, 14))

        file_inner = ttk.Frame(
            file_card,
            style="Card.TFrame"
        )
        file_inner.pack(fill="x")

        self.file_label = ttk.Label(
            file_inner,
            text="No PCAP file selected",
            style="Body.TLabel"
        )
        self.file_label.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.select_button = ttk.Button(
            file_inner,
            text="Select PCAP",
            command=self.select_pcap,
            style="Secondary.TButton"
        )
        self.select_button.pack(
            side="right",
            padx=(10, 0)
        )

        self.case_status_label = ttk.Label(
            file_card,
            text="No investigation case loaded",
            style="CardMuted.TLabel"
        )
        self.case_status_label.pack(
            anchor="w",
            pady=(7, 0)
        )

        controls_frame = ttk.Frame(
            main_frame,
            style="Main.TFrame"
        )
        controls_frame.pack(fill="x", pady=(0, 10))

        self.analyze_button = ttk.Button(
            controls_frame,
            text="Analyze PCAP",
            command=self.start_analysis,
            state="disabled",
            style="Primary.TButton"
        )
        self.analyze_button.pack(side="left")

        self.save_case_button = ttk.Button(
            controls_frame,
            text="Save Case",
            command=self.save_investigation_case,
            state="disabled",
            style="Secondary.TButton"
        )
        self.save_case_button.pack(
            side="left",
            padx=(10, 0)
        )

        self.load_case_button = ttk.Button(
            controls_frame,
            text="Load Case",
            command=self.load_investigation_case,
            style="Secondary.TButton"
        )
        self.load_case_button.pack(
            side="left",
            padx=(10, 0)
        )

        self.status_label = ttk.Label(
            controls_frame,
            text="Ready",
            style="Status.TLabel"
        )
        self.status_label.pack(
            side="left",
            padx=(15, 0)
        )

        options_card = ttk.LabelFrame(
            main_frame,
            text="Analysis Options",
            style="Card.TLabelframe",
            padding=10
        )
        options_card.pack(fill="x", pady=(0, 12))

        options_inner = ttk.Frame(
            options_card,
            style="Card.TFrame"
        )
        options_inner.pack(fill="x")

        ai_row = ttk.Frame(
            options_inner,
            style="Card.TFrame"
        )
        ai_row.pack(fill="x")

        self.ai_checkbox = ttk.Checkbutton(
            ai_row,
            text="Generate AI Explanation",
            variable=self.generate_ai_var,
            style="Option.TCheckbutton"
        )
        self.ai_checkbox.pack(side="left")

        ttk.Label(
            ai_row,
            text="Provider:",
            style="Body.TLabel"
        ).pack(side="left", padx=(18, 6))

        self.ai_provider_combo = ttk.Combobox(
            ai_row,
            textvariable=self.ai_provider_var,
            values=[
                "Local Ollama",
                "OpenAI API"
            ],
            state="readonly",
            width=14
        )
        self.ai_provider_combo.pack(side="left")
        self.ai_provider_combo.bind(
            "<<ComboboxSelected>>",
            self.on_ai_provider_changed
        )

        ttk.Label(
            ai_row,
            text="Model:",
            style="Body.TLabel"
        ).pack(side="left", padx=(14, 6))

        self.ollama_model_entry = tk.Entry(
            ai_row,
            textvariable=self.ollama_model_var,
            width=22,
            font=("Segoe UI", 9),
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#374151",
            highlightcolor="#60a5fa"
        )
        self.ollama_model_entry.pack(
            side="left",
            ipady=4
        )

        self.test_local_ai_button = ttk.Button(
            ai_row,
            text="Test Local AI",
            command=self.start_local_ai_test,
            style="Secondary.TButton"
        )
        self.test_local_ai_button.pack(
            side="left",
            padx=(10, 0)
        )

        report_option_row = ttk.Frame(
            options_inner,
            style="Card.TFrame"
        )
        report_option_row.pack(fill="x", pady=(8, 0))

        self.save_checkbox = ttk.Checkbutton(
            report_option_row,
            text="Save TXT + JSON + CSV Reports",
            variable=self.save_reports_var,
            style="Option.TCheckbutton"
        )
        self.save_checkbox.pack(side="left")

        self.ollama_status_label = ttk.Label(
            report_option_row,
            textvariable=self.ollama_test_status_var,
            style="CardMuted.TLabel"
        )
        self.ollama_status_label.pack(
            side="right"
        )

        self.options_note = ttk.Label(
            options_card,
            text=(
                "Local Ollama keeps AI prompts on this computer. "
                "The model receives bounded structured findings and metadata, "
                "not raw packet payloads."
            ),
            style="CardMuted.TLabel",
            wraplength=1000,
            justify="left"
        )
        self.options_note.pack(anchor="w", pady=(7, 0))

        self.on_ai_provider_changed()

        self.progress_bar = ttk.Progressbar(
            main_frame,
            mode="determinate",
            maximum=100,
            value=0,
            style="Green.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(
            fill="x",
            pady=(0, 12)
        )

        report_card = ttk.LabelFrame(
            main_frame,
            text="Report Actions",
            style="Card.TLabelframe",
            padding=10
        )
        report_card.pack(fill="x", pady=(0, 15))

        report_controls = ttk.Frame(
            report_card,
            style="Card.TFrame"
        )
        report_controls.pack(fill="x")

        self.open_txt_button = ttk.Button(
            report_controls,
            text="Open TXT Report",
            command=self.open_txt_report,
            state="disabled",
            style="Secondary.TButton"
        )
        self.open_txt_button.pack(side="left")

        self.open_json_button = ttk.Button(
            report_controls,
            text="Open JSON Report",
            command=self.open_json_report,
            state="disabled",
            style="Secondary.TButton"
        )
        self.open_json_button.pack(side="left", padx=(10, 0))

        self.open_csv_button = ttk.Button(
            report_controls,
            text="Open Packet CSV",
            command=self.open_csv_report,
            state="disabled",
            style="Secondary.TButton"
        )
        self.open_csv_button.pack(side="left", padx=(10, 0))

        self.open_folder_button = ttk.Button(
            report_controls,
            text="Open Report Folder",
            command=self.open_report_folder,
            state="disabled",
            style="Secondary.TButton"
        )
        self.open_folder_button.pack(side="left", padx=(10, 0))

        summary_row = ttk.Frame(
            main_frame,
            style="Main.TFrame"
        )
        summary_row.pack(fill="x", pady=(0, 15))

        self.assessment_card = self.create_summary_card(
            summary_row,
            "Assessment",
            "Not Analyzed"
        )

        self.score_card = self.create_summary_card(
            summary_row,
            "Risk Score",
            "-- / 100"
        )

        self.packet_card = self.create_summary_card(
            summary_row,
            "Packets Analyzed",
            "--"
        )

        threat_card = ttk.LabelFrame(
            main_frame,
            text="Threat Categories",
            style="Card.TLabelframe",
            padding=12
        )
        threat_card.pack(fill="x", pady=(0, 15))

        self.categories_label = ttk.Label(
            threat_card,
            text="None detected",
            style="Body.TLabel",
            wraplength=1000,
            justify="left"
        )
        self.categories_label.pack(anchor="w")

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(
            fill="x",
            expand=False
        )
        self.notebook.configure(height=360)

        self.overview_tab = self.create_text_tab(
            "Overview"
        )

        self.portscan_tab = self.create_text_tab(
            "Port Scans"
        )

        self.dns_tab = self.create_text_tab(
            "DNS"
        )

        self.outbound_tab = self.create_text_tab(
            "Outbound Activity"
        )

        self.threat_hunt_tab = self.create_threat_hunt_tab()

        self.investigation_queue_tab = self.create_investigation_queue_tab()

        self.finding_tab = self.create_finding_investigation_tab()

        self.visual_tab = self.create_visual_analysis_tab()

        self.host_tab = self.create_host_investigation_tab()

        self.full_tab = self.create_text_tab(
            "Full Analysis"
        )

        footer = ttk.Label(
            main_frame,
            text=(
                "Behavioral findings are indicators for defensive review, "
                "not proof of compromise."
            ),
            style="Muted.TLabel"
        )
        footer.pack(anchor="w", pady=(10, 0))

    def update_main_scrollregion(self, event=None):
        self.main_canvas.configure(
            scrollregion=self.main_canvas.bbox("all")
        )

    def resize_main_content(self, event):
        self.main_canvas.itemconfigure(
            self.main_window,
            width=event.width
        )

    def bind_mousewheel(self, widget):
        widget.bind_all(
            "<MouseWheel>",
            self.on_mousewheel
        )

    def on_mousewheel(self, event):
        if not self.main_canvas.winfo_exists():
            return

        pointer_widget = self.root.winfo_containing(
            self.root.winfo_pointerx(),
            self.root.winfo_pointery()
        )

        if pointer_widget is None:
            return

        # Let text tabs keep their own scrolling behavior.
        current = pointer_widget
        while current is not None:
            if isinstance(current, tk.Text):
                return

            parent_name = current.winfo_parent()
            if not parent_name:
                break

            try:
                current = current._nametowidget(parent_name)
            except Exception:
                break

        self.main_canvas.yview_scroll(
            int(-1 * (event.delta / 120)),
            "units"
        )

    def create_summary_card(
        self,
        parent,
        title,
        value
    ):
        card = ttk.Frame(
            parent,
            style="Card.TFrame",
            padding=15
        )

        card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        title_label = ttk.Label(
            card,
            text=title,
            style="CardTitle.TLabel"
        )
        title_label.pack()

        value_label = ttk.Label(
            card,
            text=value,
            style="CardValue.TLabel"
        )
        value_label.pack(pady=(6, 0))

        return value_label

    def create_text_tab(self, title):
        frame = ttk.Frame(
            self.notebook,
            style="Card.TFrame"
        )

        self.notebook.add(
            frame,
            text=title
        )

        container = ttk.Frame(
            frame,
            style="Card.TFrame",
            padding=8
        )
        container.pack(
            fill="both",
            expand=True
        )

        scrollbar = ttk.Scrollbar(
            container,
            orient="vertical"
        )
        scrollbar.pack(
            side="right",
            fill="y"
        )

        text_widget = tk.Text(
            container,
            wrap="word",
            font=("Consolas", 10),
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=12,
            pady=12,
            yscrollcommand=scrollbar.set,
            state="disabled"
        )

        text_widget.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.config(
            command=text_widget.yview
        )

        return text_widget

    def create_threat_hunt_tab(self):
        frame = ttk.Frame(
            self.notebook,
            style="Card.TFrame"
        )

        self.notebook.add(
            frame,
            text="Threat Hunt"
        )

        container = ttk.Frame(
            frame,
            style="Card.TFrame",
            padding=10
        )
        container.pack(
            fill="both",
            expand=True
        )

        # ----------------------------------------------------------
        # SEARCH CONTROLS
        # ----------------------------------------------------------
        search_row = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        search_row.pack(
            fill="x",
            pady=(0, 8)
        )

        ttk.Label(
            search_row,
            text="Hunt:",
            style="Body.TLabel"
        ).pack(
            side="left",
            padx=(0, 8)
        )

        self.threat_hunt_type_var = tk.StringVar(
            value="Auto"
        )

        self.threat_hunt_type_combo = ttk.Combobox(
            search_row,
            textvariable=self.threat_hunt_type_var,
            values=[
                "Auto",
                "IP Address",
                "Domain",
                "Destination Port",
                "Protocol",
                "Finding ID"
            ],
            state="readonly",
            width=17
        )
        self.threat_hunt_type_combo.pack(
            side="left",
            padx=(0, 8)
        )

        self.threat_hunt_query_var = tk.StringVar()

        self.threat_hunt_query_entry = tk.Entry(
            search_row,
            textvariable=self.threat_hunt_query_var,
            font=("Segoe UI", 10),
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#374151",
            highlightcolor="#60a5fa"
        )
        self.threat_hunt_query_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=6,
            padx=(0, 8)
        )

        self.threat_hunt_query_entry.bind(
            "<Return>",
            lambda event: self.run_threat_hunt_search()
        )

        self.threat_hunt_search_button = ttk.Button(
            search_row,
            text="Search",
            command=self.run_threat_hunt_search,
            style="Primary.TButton"
        )
        self.threat_hunt_search_button.pack(
            side="left"
        )

        self.threat_hunt_clear_button = ttk.Button(
            search_row,
            text="Clear",
            command=self.clear_threat_hunt_results,
            style="Secondary.TButton"
        )
        self.threat_hunt_clear_button.pack(
            side="left",
            padx=(8, 0)
        )

        info_row = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        info_row.pack(
            fill="x",
            pady=(0, 8)
        )

        self.threat_hunt_status_label = ttk.Label(
            info_row,
            text=(
                "Analyze a PCAP, then search by IP, domain, "
                "destination port, protocol, or finding ID."
            ),
            style="CardMuted.TLabel"
        )
        self.threat_hunt_status_label.pack(
            side="left"
        )

        ttk.Label(
            info_row,
            text=(
                "Examples: 192.168.1.115  •  bimbo09.ddns.net  •  "
                "1177  •  DNS  •  OUTBOUND-001"
            ),
            style="CardMuted.TLabel"
        ).pack(
            side="right"
        )

        # ----------------------------------------------------------
        # RESULT NOTEBOOK
        # ----------------------------------------------------------
        self.threat_hunt_results_notebook = ttk.Notebook(
            container
        )
        self.threat_hunt_results_notebook.pack(
            fill="both",
            expand=True
        )

        # Summary
        summary_frame = ttk.Frame(
            self.threat_hunt_results_notebook,
            style="Card.TFrame"
        )
        self.threat_hunt_results_notebook.add(
            summary_frame,
            text="Summary"
        )

        self.threat_hunt_summary_text = tk.Text(
            summary_frame,
            wrap="word",
            font=("Consolas", 9),
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=12,
            pady=10,
            state="disabled"
        )
        self.threat_hunt_summary_text.pack(
            fill="both",
            expand=True
        )

        # Hosts
        hosts_frame = ttk.Frame(
            self.threat_hunt_results_notebook,
            style="Card.TFrame"
        )
        self.threat_hunt_results_notebook.add(
            hosts_frame,
            text="Hosts (0)"
        )
        self.threat_hunt_hosts_frame = hosts_frame

        host_tree_container = ttk.Frame(
            hosts_frame,
            style="Card.TFrame",
            padding=6
        )
        host_tree_container.pack(
            fill="both",
            expand=True
        )

        self.threat_hunt_host_tree = ttk.Treeview(
            host_tree_container,
            columns=(
                "risk",
                "ip",
                "packets",
                "assessment"
            ),
            show="headings",
            height=8
        )

        self.threat_hunt_host_tree.heading(
            "risk",
            text="Risk"
        )
        self.threat_hunt_host_tree.heading(
            "ip",
            text="IP Address"
        )
        self.threat_hunt_host_tree.heading(
            "packets",
            text="Packets"
        )
        self.threat_hunt_host_tree.heading(
            "assessment",
            text="Assessment"
        )

        self.threat_hunt_host_tree.column(
            "risk",
            width=65,
            anchor="center"
        )
        self.threat_hunt_host_tree.column(
            "ip",
            width=240,
            anchor="w"
        )
        self.threat_hunt_host_tree.column(
            "packets",
            width=95,
            anchor="e"
        )
        self.threat_hunt_host_tree.column(
            "assessment",
            width=150,
            anchor="center"
        )

        host_scroll = ttk.Scrollbar(
            host_tree_container,
            orient="vertical",
            command=self.threat_hunt_host_tree.yview
        )
        self.threat_hunt_host_tree.configure(
            yscrollcommand=host_scroll.set
        )

        self.threat_hunt_host_tree.pack(
            side="left",
            fill="both",
            expand=True
        )
        host_scroll.pack(
            side="right",
            fill="y"
        )

        self.threat_hunt_host_tree.bind(
            "<Double-1>",
            lambda event: self.open_selected_threat_hunt_host()
        )

        host_actions = ttk.Frame(
            hosts_frame,
            style="Card.TFrame",
            padding=(6, 0, 6, 6)
        )
        host_actions.pack(fill="x")

        ttk.Button(
            host_actions,
            text="Open Host Investigation",
            command=self.open_selected_threat_hunt_host,
            style="Secondary.TButton"
        ).pack(side="left")

        ttk.Button(
            host_actions,
            text="Add Host to Queue",
            command=self.add_selected_threat_hunt_host_to_queue,
            style="Secondary.TButton"
        ).pack(side="left", padx=(8, 0))

        # Findings
        findings_frame = ttk.Frame(
            self.threat_hunt_results_notebook,
            style="Card.TFrame"
        )
        self.threat_hunt_results_notebook.add(
            findings_frame,
            text="Findings (0)"
        )
        self.threat_hunt_findings_frame = findings_frame

        finding_tree_container = ttk.Frame(
            findings_frame,
            style="Card.TFrame",
            padding=6
        )
        finding_tree_container.pack(
            fill="both",
            expand=True
        )

        self.threat_hunt_finding_tree = ttk.Treeview(
            finding_tree_container,
            columns=(
                "id",
                "risk",
                "type",
                "source"
            ),
            show="headings",
            height=8
        )

        self.threat_hunt_finding_tree.heading(
            "id",
            text="Finding ID"
        )
        self.threat_hunt_finding_tree.heading(
            "risk",
            text="Risk"
        )
        self.threat_hunt_finding_tree.heading(
            "type",
            text="Finding Type"
        )
        self.threat_hunt_finding_tree.heading(
            "source",
            text="Source / Scope"
        )

        self.threat_hunt_finding_tree.column(
            "id",
            width=120,
            anchor="w"
        )
        self.threat_hunt_finding_tree.column(
            "risk",
            width=65,
            anchor="center"
        )
        self.threat_hunt_finding_tree.column(
            "type",
            width=260,
            anchor="w"
        )
        self.threat_hunt_finding_tree.column(
            "source",
            width=220,
            anchor="w"
        )

        finding_scroll = ttk.Scrollbar(
            finding_tree_container,
            orient="vertical",
            command=self.threat_hunt_finding_tree.yview
        )
        self.threat_hunt_finding_tree.configure(
            yscrollcommand=finding_scroll.set
        )

        self.threat_hunt_finding_tree.pack(
            side="left",
            fill="both",
            expand=True
        )
        finding_scroll.pack(
            side="right",
            fill="y"
        )

        self.threat_hunt_finding_tree.bind(
            "<Double-1>",
            lambda event: self.open_selected_threat_hunt_finding()
        )

        finding_actions = ttk.Frame(
            findings_frame,
            style="Card.TFrame",
            padding=(6, 0, 6, 6)
        )
        finding_actions.pack(fill="x")

        ttk.Button(
            finding_actions,
            text="Open Finding Investigation",
            command=self.open_selected_threat_hunt_finding,
            style="Secondary.TButton"
        ).pack(side="left")

        ttk.Button(
            finding_actions,
            text="Add Finding to Queue",
            command=self.add_selected_threat_hunt_finding_to_queue,
            style="Secondary.TButton"
        ).pack(side="left", padx=(8, 0))

        # Packet Evidence
        packets_frame = ttk.Frame(
            self.threat_hunt_results_notebook,
            style="Card.TFrame"
        )
        self.threat_hunt_results_notebook.add(
            packets_frame,
            text="Packets (0)"
        )
        self.threat_hunt_packets_frame = packets_frame

        packet_tree_container = ttk.Frame(
            packets_frame,
            style="Card.TFrame",
            padding=6
        )
        packet_tree_container.pack(
            fill="both",
            expand=True
        )

        self.threat_hunt_packet_tree = ttk.Treeview(
            packet_tree_container,
            columns=(
                "packet",
                "offset",
                "source",
                "destination",
                "protocol",
                "ports",
                "findings"
            ),
            show="headings",
            height=9
        )

        packet_headings = {
            "packet": "Packet",
            "offset": "Time Offset",
            "source": "Source",
            "destination": "Destination",
            "protocol": "Protocol",
            "ports": "Ports",
            "findings": "Finding IDs"
        }

        for column, heading in packet_headings.items():
            self.threat_hunt_packet_tree.heading(
                column,
                text=heading
            )

        packet_widths = {
            "packet": 70,
            "offset": 95,
            "source": 180,
            "destination": 180,
            "protocol": 80,
            "ports": 120,
            "findings": 150
        }

        for column, width in packet_widths.items():
            self.threat_hunt_packet_tree.column(
                column,
                width=width,
                anchor=(
                    "center"
                    if column in {
                        "packet",
                        "offset",
                        "protocol",
                        "ports"
                    }
                    else "w"
                )
            )

        packet_y_scroll = ttk.Scrollbar(
            packet_tree_container,
            orient="vertical",
            command=self.threat_hunt_packet_tree.yview
        )
        packet_x_scroll = ttk.Scrollbar(
            packets_frame,
            orient="horizontal",
            command=self.threat_hunt_packet_tree.xview
        )

        self.threat_hunt_packet_tree.configure(
            yscrollcommand=packet_y_scroll.set,
            xscrollcommand=packet_x_scroll.set
        )

        self.threat_hunt_packet_tree.pack(
            side="left",
            fill="both",
            expand=True
        )
        packet_y_scroll.pack(
            side="right",
            fill="y"
        )
        packet_x_scroll.pack(
            fill="x",
            padx=6,
            pady=(0, 6)
        )

        self.threat_hunt_packet_tree.bind(
            "<<TreeviewSelect>>",
            self.on_threat_hunt_packet_selected
        )

        self.threat_hunt_packet_tree.bind(
            "<Double-1>",
            lambda event: self.open_selected_threat_hunt_packet_on_timeline()
        )

        packet_actions = ttk.Frame(
            packets_frame,
            style="Card.TFrame",
            padding=(6, 0, 6, 6)
        )
        packet_actions.pack(fill="x")

        ttk.Button(
            packet_actions,
            text="Show Selected Packet on Timeline",
            command=self.open_selected_threat_hunt_packet_on_timeline,
            style="Secondary.TButton"
        ).pack(side="left")

        ttk.Button(
            packet_actions,
            text="Add Selected Packet to Queue",
            command=self.add_selected_threat_hunt_packet_to_queue,
            style="Secondary.TButton"
        ).pack(side="left", padx=(8, 0))

        # Relationships
        relationships_frame = ttk.Frame(
            self.threat_hunt_results_notebook,
            style="Card.TFrame"
        )
        self.threat_hunt_results_notebook.add(
            relationships_frame,
            text="Relationships (0)"
        )
        self.threat_hunt_relationships_frame = relationships_frame

        relationship_tree_container = ttk.Frame(
            relationships_frame,
            style="Card.TFrame",
            padding=6
        )
        relationship_tree_container.pack(
            fill="both",
            expand=True
        )

        self.threat_hunt_relationship_tree = ttk.Treeview(
            relationship_tree_container,
            columns=(
                "source",
                "target",
                "packets",
                "bytes"
            ),
            show="headings",
            height=9
        )

        self.threat_hunt_relationship_tree.heading(
            "source",
            text="Host A"
        )
        self.threat_hunt_relationship_tree.heading(
            "target",
            text="Host B"
        )
        self.threat_hunt_relationship_tree.heading(
            "packets",
            text="Packets"
        )
        self.threat_hunt_relationship_tree.heading(
            "bytes",
            text="Bytes"
        )

        self.threat_hunt_relationship_tree.column(
            "source",
            width=250,
            anchor="w"
        )
        self.threat_hunt_relationship_tree.column(
            "target",
            width=250,
            anchor="w"
        )
        self.threat_hunt_relationship_tree.column(
            "packets",
            width=100,
            anchor="e"
        )
        self.threat_hunt_relationship_tree.column(
            "bytes",
            width=120,
            anchor="e"
        )

        relationship_scroll = ttk.Scrollbar(
            relationship_tree_container,
            orient="vertical",
            command=self.threat_hunt_relationship_tree.yview
        )
        self.threat_hunt_relationship_tree.configure(
            yscrollcommand=relationship_scroll.set
        )

        self.threat_hunt_relationship_tree.pack(
            side="left",
            fill="both",
            expand=True
        )
        relationship_scroll.pack(
            side="right",
            fill="y"
        )

        self.threat_hunt_result = None
        self.threat_hunt_host_records = []
        self.threat_hunt_finding_records = []
        self.threat_hunt_packet_records = []
        self.selected_threat_hunt_packet = None

        self.set_text(
            self.threat_hunt_summary_text,
            (
                "THREAT HUNT\n"
                "===========\n\n"
                "Analyze a PCAP, then search the indexed capture data.\n\n"
                "Supported searches:\n"
                "  • IP address\n"
                "  • Domain\n"
                "  • Destination port\n"
                "  • Protocol\n"
                "  • Finding ID\n\n"
                "Searches reuse bounded metadata already collected by the "
                "analyzer. They do not reread the PCAP or display packet payloads."
            )
        )

        return frame

    def initialize_threat_hunt(self, report):
        backend = report.get(
            "threat_hunt",
            {}
        )

        if not backend:
            self.threat_hunt_status_label.config(
                text="Threat Hunt index is unavailable for this analysis."
            )
            return

        self.threat_hunt_status_label.config(
            text=(
                f"Ready: {backend.get('host_count', 0):,} hosts  •  "
                f"{backend.get('domain_count', 0):,} domains  •  "
                f"{backend.get('destination_port_count', 0):,} destination ports  •  "
                f"{backend.get('protocol_count', 0):,} protocols  •  "
                f"{backend.get('finding_count', 0):,} findings"
            )
        )

        self.set_text(
            self.threat_hunt_summary_text,
            (
                "THREAT HUNT READY\n"
                "=================\n\n"
                "Search this analyzed capture using the controls above.\n\n"
                f"Indexed hosts:              {backend.get('host_count', 0):,}\n"
                f"Indexed domains:            {backend.get('domain_count', 0):,}\n"
                f"Indexed destination ports:  {backend.get('destination_port_count', 0):,}\n"
                f"Indexed protocols:          {backend.get('protocol_count', 0):,}\n"
                f"Indexed findings:           {backend.get('finding_count', 0):,}\n"
                f"Representative packets:     {backend.get('packet_evidence_count', 0):,}\n\n"
                "Packet evidence is intentionally bounded and metadata-only."
            )
        )

    def run_threat_hunt_search(self):
        if not self.report_data:
            messagebox.showinfo(
                "Analyze a PCAP First",
                "Analyze a PCAP before using Threat Hunt."
            )
            return

        query = self.threat_hunt_query_var.get().strip()

        if not query:
            messagebox.showinfo(
                "Enter a Search",
                "Enter an IP, domain, port, protocol, or finding ID."
            )
            return

        query_type_map = {
            "Auto": "auto",
            "IP Address": "ip",
            "Domain": "domain",
            "Destination Port": "port",
            "Protocol": "protocol",
            "Finding ID": "finding_id"
        }

        query_type = query_type_map.get(
            self.threat_hunt_type_var.get(),
            "auto"
        )

        try:
            result = search_threat_hunt(
                self.report_data,
                query,
                query_type=query_type,
                limit=100
            )
        except Exception as error:
            messagebox.showerror(
                "Threat Hunt Error",
                (
                    "The threat-hunt search could not be completed.\n\n"
                    f"{error}"
                )
            )
            return

        self.display_threat_hunt_result(result)

    def clear_threat_hunt_results(self):
        self.threat_hunt_query_var.set("")
        self.threat_hunt_result = None
        self.threat_hunt_host_records = []
        self.threat_hunt_finding_records = []
        self.threat_hunt_packet_records = []
        self.selected_threat_hunt_packet = None

        for tree_name in [
            "threat_hunt_host_tree",
            "threat_hunt_finding_tree",
            "threat_hunt_packet_tree",
            "threat_hunt_relationship_tree"
        ]:
            tree = getattr(
                self,
                tree_name,
                None
            )

            if tree is not None:
                for item in tree.get_children():
                    tree.delete(item)

        if hasattr(
            self,
            "threat_hunt_results_notebook"
        ):
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_hosts_frame,
                text="Hosts (0)"
            )
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_findings_frame,
                text="Findings (0)"
            )
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_packets_frame,
                text="Packets (0)"
            )
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_relationships_frame,
                text="Relationships (0)"
            )

        if self.report_data:
            self.initialize_threat_hunt(
                self.report_data
            )
        else:
            self.threat_hunt_status_label.config(
                text=(
                    "Analyze a PCAP, then search by IP, domain, "
                    "destination port, protocol, or finding ID."
                )
            )

    def display_threat_hunt_result(self, result):
        self.threat_hunt_result = result

        hosts = result.get(
            "hosts",
            []
        )
        domains = result.get(
            "domains",
            []
        )
        ports = result.get(
            "destination_ports",
            []
        )
        protocols = result.get(
            "protocols",
            []
        )
        findings = result.get(
            "findings",
            []
        )
        packets = result.get(
            "packet_evidence",
            []
        )
        relationships = result.get(
            "relationships",
            []
        )

        self.threat_hunt_host_records = hosts
        self.threat_hunt_finding_records = findings
        self.threat_hunt_packet_records = packets

        for tree in [
            self.threat_hunt_host_tree,
            self.threat_hunt_finding_tree,
            self.threat_hunt_packet_tree,
            self.threat_hunt_relationship_tree
        ]:
            for item in tree.get_children():
                tree.delete(item)

        # Hosts
        for index, host in enumerate(hosts):
            packet_total = (
                host.get(
                    "packets_sent",
                    0
                )
                + host.get(
                    "packets_received",
                    0
                )
            )

            self.threat_hunt_host_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    f"{host.get('risk_score', 0)}/100",
                    host.get(
                        "ip",
                        "Unknown"
                    ),
                    f"{packet_total:,}",
                    host.get(
                        "assessment",
                        "UNKNOWN"
                    )
                )
            )

        # Findings
        for index, finding in enumerate(findings):
            self.threat_hunt_finding_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    finding.get(
                        "finding_id",
                        "Unknown"
                    ),
                    f"{finding.get('risk_score', 0)}/100",
                    finding.get(
                        "type",
                        "Unknown"
                    ),
                    finding.get(
                        "source",
                        "Unknown"
                    )
                )
            )

        # Packet Evidence
        for index, packet in enumerate(packets):
            source_port = packet.get(
                "source_port"
            )
            destination_port = packet.get(
                "destination_port"
            )

            if (
                source_port is not None
                or destination_port is not None
            ):
                ports_text = (
                    f"{source_port if source_port is not None else '-'}"
                    f" → "
                    f"{destination_port if destination_port is not None else '-'}"
                )
            else:
                ports_text = "N/A"

            offset = packet.get(
                "offset_seconds"
            )

            if isinstance(
                offset,
                (int, float)
            ):
                offset_text = f"{offset:.3f}s"
            else:
                offset_text = "N/A"

            finding_ids = ", ".join(
                packet.get(
                    "finding_ids",
                    []
                )
            ) or "—"

            self.threat_hunt_packet_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    packet.get(
                        "packet_number",
                        "?"
                    ),
                    offset_text,
                    packet.get(
                        "source",
                        "Unknown"
                    ),
                    packet.get(
                        "destination",
                        "Unknown"
                    ),
                    packet.get(
                        "protocol",
                        "Unknown"
                    ),
                    ports_text,
                    finding_ids
                )
            )

        # Relationships
        for index, relationship in enumerate(
            relationships
        ):
            self.threat_hunt_relationship_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    relationship.get(
                        "source",
                        relationship.get(
                            "host_a",
                            "Unknown"
                        )
                    ),
                    relationship.get(
                        "target",
                        relationship.get(
                            "host_b",
                            "Unknown"
                        )
                    ),
                    f"{relationship.get('packets', 0):,}",
                    f"{relationship.get('bytes', 0):,}"
                )
            )

        self.threat_hunt_results_notebook.tab(
            self.threat_hunt_hosts_frame,
            text=f"Hosts ({len(hosts)})"
        )
        self.threat_hunt_results_notebook.tab(
            self.threat_hunt_findings_frame,
            text=f"Findings ({len(findings)})"
        )
        self.threat_hunt_results_notebook.tab(
            self.threat_hunt_packets_frame,
            text=f"Packets ({len(packets)})"
        )
        self.threat_hunt_results_notebook.tab(
            self.threat_hunt_relationships_frame,
            text=f"Relationships ({len(relationships)})"
        )

        resolved_type = result.get(
            "resolved_type",
            "unknown"
        )
        match_count = result.get(
            "match_count",
            0
        )

        self.threat_hunt_status_label.config(
            text=(
                f"Search complete: {match_count} indexed match"
                f"{'' if match_count == 1 else 'es'}  •  "
                f"resolved as {resolved_type}"
            )
        )

        lines = [
            "THREAT HUNT RESULTS",
            "=" * 70,
            "",
            f"Query:          {result.get('query', '')}",
            f"Resolved Type:  {resolved_type}",
            f"Indexed Matches:{match_count:>5}",
            "",
            "RESULT COUNTS",
            "-" * 70,
            f"Hosts:          {len(hosts):,}",
            f"Domains:        {len(domains):,}",
            f"Ports:          {len(ports):,}",
            f"Protocols:      {len(protocols):,}",
            f"Findings:       {len(findings):,}",
            f"Packets:        {len(packets):,}",
            f"Relationships:  {len(relationships):,}",
            ""
        ]

        if domains:
            lines.extend([
                "DOMAIN MATCHES",
                "-" * 70
            ])

            for domain in domains[:10]:
                lines.append(
                    f"{domain.get('domain', 'Unknown')}  "
                    f"({domain.get('queries', 0):,} queries)"
                )

            lines.append("")

        if ports:
            lines.extend([
                "DESTINATION PORT MATCHES",
                "-" * 70
            ])

            for port in ports[:10]:
                lines.append(
                    f"Port {port.get('port', '?')}: "
                    f"{port.get('packets', 0):,} packets from "
                    f"{port.get('source_host_count', 0):,} source host(s)"
                )

            lines.append("")

        if protocols:
            lines.extend([
                "PROTOCOL MATCHES",
                "-" * 70
            ])

            for protocol in protocols[:10]:
                lines.append(
                    f"{protocol.get('protocol', 'Unknown')}: "
                    f"{protocol.get('packets', 0):,} packets"
                )

            lines.append("")

        if findings:
            lines.extend([
                "RELATED FINDINGS",
                "-" * 70
            ])

            for finding in findings[:10]:
                lines.append(
                    f"{finding.get('finding_id', 'Unknown')}  |  "
                    f"{finding.get('risk_score', 0)}/100  |  "
                    f"{finding.get('title', finding.get('type', 'Unknown'))}"
                )

            lines.append("")

        if match_count == 0:
            lines.extend([
                "No indexed matches were found.",
                "",
                (
                    "Try Auto search or verify the IP, domain, port, "
                    "protocol, or finding ID."
                )
            ])

        lines.extend([
            "",
            (
                "Threat Hunt searches metadata collected during analysis. "
                "Representative packet evidence is intentionally bounded, "
                "and packet payload content is not displayed."
            )
        ])

        self.set_text(
            self.threat_hunt_summary_text,
            "\n".join(lines)
        )

        self.threat_hunt_results_notebook.select(
            0
        )

    def open_selected_threat_hunt_host(self):
        selection = self.threat_hunt_host_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a Host",
                "Select a host result first."
            )
            return

        try:
            index = int(selection[0])
            host = self.threat_hunt_host_records[
                index
            ]
        except Exception:
            return

        self.open_host_by_ip(
            host.get("ip")
        )

    def open_selected_threat_hunt_finding(self):
        selection = self.threat_hunt_finding_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a Finding",
                "Select a finding result first."
            )
            return

        try:
            index = int(selection[0])
            finding = self.threat_hunt_finding_records[
                index
            ]
        except Exception:
            return

        self.open_finding_by_id(
            finding.get("finding_id")
        )

    def create_investigation_queue_tab(self):
        frame = ttk.Frame(
            self.notebook,
            style="Card.TFrame"
        )

        self.notebook.add(
            frame,
            text="Investigation Queue"
        )

        container = ttk.Frame(
            frame,
            style="Card.TFrame",
            padding=10
        )
        container.pack(
            fill="both",
            expand=True
        )

        header = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        header.pack(
            fill="x",
            pady=(0, 8)
        )

        ttk.Label(
            header,
            text="Analyst Investigation Queue",
            style="Body.TLabel"
        ).pack(side="left")

        self.queue_count_label = ttk.Label(
            header,
            text="0 items",
            style="CardMuted.TLabel"
        )
        self.queue_count_label.pack(
            side="right",
            padx=(8, 0)
        )

        self.queue_export_button = ttk.Button(
            header,
            text="Export Queue",
            command=self.export_investigation_queue,
            style="Secondary.TButton"
        )
        self.queue_export_button.pack(
            side="right"
        )

        ttk.Label(
            container,
            text=(
                "Bookmark findings, hosts, and representative packets while "
                "you investigate. Add notes, reopen items, or export the queue "
                "for case handoff."
            ),
            style="CardMuted.TLabel"
        ).pack(
            anchor="w",
            pady=(0, 8)
        )

        body = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        body.pack(
            fill="both",
            expand=True
        )

        # ------------------------------------------------------
        # LEFT: QUEUED ITEMS
        # ------------------------------------------------------
        left = ttk.Frame(
            body,
            style="Card.TFrame"
        )
        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 10)
        )

        queue_tree_frame = ttk.Frame(
            left,
            style="Card.TFrame"
        )
        queue_tree_frame.pack(
            fill="both",
            expand=True
        )

        queue_scroll = ttk.Scrollbar(
            queue_tree_frame,
            orient="vertical"
        )
        queue_scroll.pack(
            side="right",
            fill="y"
        )

        self.investigation_queue_tree = ttk.Treeview(
            queue_tree_frame,
            columns=(
                "type",
                "item",
                "context",
                "note"
            ),
            show="headings",
            height=12,
            yscrollcommand=queue_scroll.set
        )
        self.investigation_queue_tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        queue_scroll.config(
            command=self.investigation_queue_tree.yview
        )

        headings = {
            "type": "Type",
            "item": "Item",
            "context": "Risk / Context",
            "note": "Analyst Note"
        }

        for column, label in headings.items():
            self.investigation_queue_tree.heading(
                column,
                text=label
            )

        self.investigation_queue_tree.column(
            "type",
            width=90,
            minwidth=75,
            anchor="center",
            stretch=False
        )
        self.investigation_queue_tree.column(
            "item",
            width=220,
            minwidth=150,
            anchor="w",
            stretch=True
        )
        self.investigation_queue_tree.column(
            "context",
            width=180,
            minwidth=130,
            anchor="w",
            stretch=True
        )
        self.investigation_queue_tree.column(
            "note",
            width=260,
            minwidth=160,
            anchor="w",
            stretch=True
        )

        self.investigation_queue_tree.bind(
            "<<TreeviewSelect>>",
            self.on_investigation_queue_selected
        )

        self.investigation_queue_tree.bind(
            "<Double-1>",
            lambda event: self.open_selected_queue_item()
        )

        queue_actions = ttk.Frame(
            left,
            style="Card.TFrame"
        )
        queue_actions.pack(
            fill="x",
            pady=(8, 0)
        )

        ttk.Button(
            queue_actions,
            text="Open Selected",
            command=self.open_selected_queue_item,
            style="Secondary.TButton"
        ).pack(side="left")

        ttk.Button(
            queue_actions,
            text="Remove",
            command=self.remove_selected_queue_item,
            style="Secondary.TButton"
        ).pack(
            side="left",
            padx=(8, 0)
        )

        ttk.Button(
            queue_actions,
            text="Clear Queue",
            command=self.clear_investigation_queue,
            style="Secondary.TButton"
        ).pack(
            side="left",
            padx=(8, 0)
        )

        ttk.Label(
            queue_actions,
            text="Tip: double-click an item to reopen it.",
            style="CardMuted.TLabel"
        ).pack(
            side="right"
        )

        # ------------------------------------------------------
        # RIGHT: DETAILS + NOTE
        # ------------------------------------------------------
        right = ttk.Frame(
            body,
            style="Card.TFrame"
        )
        right.pack(
            side="left",
            fill="both",
            expand=True
        )

        ttk.Label(
            right,
            text="Selected Queue Item",
            style="Body.TLabel"
        ).pack(
            anchor="w",
            pady=(0, 6)
        )

        self.queue_detail_text = tk.Text(
            right,
            height=10,
            wrap="word",
            font=("Consolas", 9),
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=10,
            pady=8,
            state="disabled"
        )
        self.queue_detail_text.pack(
            fill="both",
            expand=True
        )

        ttk.Label(
            right,
            text="Analyst Note",
            style="Body.TLabel"
        ).pack(
            anchor="w",
            pady=(10, 6)
        )

        self.queue_note_text = tk.Text(
            right,
            height=5,
            wrap="word",
            font=("Segoe UI", 9),
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=10,
            pady=8
        )
        self.queue_note_text.pack(
            fill="x"
        )

        note_action_row = ttk.Frame(
            right,
            style="Card.TFrame"
        )
        note_action_row.pack(
            fill="x",
            pady=(8, 0)
        )

        ttk.Button(
            note_action_row,
            text="Save Note",
            command=self.save_investigation_queue_note,
            style="Primary.TButton"
        ).pack(
            side="left"
        )

        self.queue_note_status_label = ttk.Label(
            note_action_row,
            text="",
            style="CardMuted.TLabel"
        )
        self.queue_note_status_label.pack(
            side="left",
            padx=(10, 0)
        )

        self.queue_note_text.bind(
            "<FocusOut>",
            self.auto_save_investigation_queue_note
        )

        self.investigation_queue_records = []
        self.current_queue_index = None

        self.set_text(
            self.queue_detail_text,
            (
                "Select a queued item to review its context.\n\n"
                "Items can be added from Finding Investigation, "
                "Host Investigation, Packet Evidence, or Threat Hunt."
            )
        )

        return frame

    def make_queue_key(self, item_type, identifier):
        return (
            str(item_type).strip().lower(),
            str(identifier).strip().lower()
        )

    def add_to_investigation_queue(
        self,
        item_type,
        identifier,
        context="",
        payload=None
    ):
        if not identifier:
            return

        key = self.make_queue_key(
            item_type,
            identifier
        )

        for index, existing in enumerate(
            self.investigation_queue_records
        ):
            if existing.get("key") == key:
                self.current_queue_index = index
                self.refresh_investigation_queue(
                    select_index=index
                )
                self.notebook.select(
                    self.investigation_queue_tab
                )
                return

        record = {
            "key": key,
            "type": str(item_type),
            "identifier": str(identifier),
            "context": str(context),
            "note": "",
            "payload": payload or {}
        }

        self.investigation_queue_records.append(
            record
        )

        new_index = (
            len(self.investigation_queue_records)
            - 1
        )

        self.refresh_investigation_queue(
            select_index=new_index
        )

        self.notebook.select(
            self.investigation_queue_tab
        )

    def refresh_investigation_queue(
        self,
        select_index=None
    ):
        if not hasattr(
            self,
            "investigation_queue_tree"
        ):
            return

        for item in self.investigation_queue_tree.get_children():
            self.investigation_queue_tree.delete(item)

        for index, record in enumerate(
            self.investigation_queue_records
        ):
            note = record.get(
                "note",
                ""
            ).replace(
                "\n",
                " "
            ).strip()

            if len(note) > 55:
                note = note[:52] + "..."

            self.investigation_queue_tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    record.get("type", ""),
                    record.get("identifier", ""),
                    record.get("context", ""),
                    note
                )
            )

        count = len(
            self.investigation_queue_records
        )

        self.queue_count_label.config(
            text=(
                f"{count} item"
                if count == 1
                else f"{count} items"
            )
        )

        if (
            select_index is not None
            and 0 <= select_index < count
        ):
            item_id = str(select_index)
            self.investigation_queue_tree.selection_set(
                item_id
            )
            self.investigation_queue_tree.focus(
                item_id
            )
            self.investigation_queue_tree.see(
                item_id
            )
            self.show_investigation_queue_record(
                select_index
            )
        elif count == 0:
            self.current_queue_index = None
            self.queue_note_text.delete(
                "1.0",
                "end"
            )
            self.set_text(
                self.queue_detail_text,
                "The investigation queue is empty."
            )

    def on_investigation_queue_selected(
        self,
        event=None
    ):
        selection = self.investigation_queue_tree.selection()

        if not selection:
            return

        try:
            index = int(selection[0])
        except Exception:
            return

        # Preserve any note edits on the previously selected item
        # before switching the detail panel to another queue record.
        if (
            self.current_queue_index is not None
            and self.current_queue_index != index
        ):
            self.persist_current_queue_note(
                show_status=False
            )

        self.show_investigation_queue_record(
            index
        )

    def show_investigation_queue_record(
        self,
        index
    ):
        if not (
            0 <= index
            < len(self.investigation_queue_records)
        ):
            return

        self.current_queue_index = index
        record = self.investigation_queue_records[
            index
        ]

        payload = record.get(
            "payload",
            {}
        )

        lines = [
            f"Type: {record.get('type', '')}",
            f"Item: {record.get('identifier', '')}",
            f"Context: {record.get('context', '')}",
            ""
        ]

        item_type = record.get(
            "type",
            ""
        ).lower()

        if item_type == "finding":
            lines.extend([
                f"Title: {payload.get('title', payload.get('type', 'Unknown'))}",
                f"Source / Scope: {payload.get('source', 'Unknown')}",
                f"Assessment: {payload.get('assessment', 'Unknown')}",
            ])

        elif item_type == "host":
            lines.extend([
                f"Assessment: {payload.get('assessment', 'Unknown')}",
                f"Packets sent: {payload.get('packets_sent', 0):,}",
                f"Packets received: {payload.get('packets_received', 0):,}",
                (
                    "Threat categories: "
                    + (
                        ", ".join(
                            payload.get(
                                "threat_categories",
                                []
                            )
                        )
                        or "None detected"
                    )
                )
            ])

        elif item_type == "packet":
            lines.extend([
                f"Packet number: {payload.get('packet_number', '?')}",
                f"Capture offset: {payload.get('offset_seconds', 'Unknown')}",
                f"Source: {payload.get('source', 'Unknown')}",
                f"Destination: {payload.get('destination', 'Unknown')}",
                f"Protocol: {payload.get('protocol', 'Unknown')}",
                f"Destination port: {payload.get('destination_port', 'N/A')}",
            ])

        self.set_text(
            self.queue_detail_text,
            "\n".join(lines)
        )

        self.queue_note_text.delete(
            "1.0",
            "end"
        )
        self.queue_note_text.insert(
            "1.0",
            record.get(
                "note",
                ""
            )
        )

    def persist_current_queue_note(
        self,
        show_status=False
    ):
        index = self.current_queue_index

        if index is None:
            return False

        if not (
            0 <= index
            < len(self.investigation_queue_records)
        ):
            return False

        note = self.queue_note_text.get(
            "1.0",
            "end"
        ).strip()

        self.investigation_queue_records[
            index
        ]["note"] = note

        item_id = str(index)

        if self.investigation_queue_tree.exists(
            item_id
        ):
            record = self.investigation_queue_records[
                index
            ]

            note_preview = note.replace(
                "\n",
                " "
            ).strip()

            if len(note_preview) > 55:
                note_preview = (
                    note_preview[:52]
                    + "..."
                )

            self.investigation_queue_tree.item(
                item_id,
                values=(
                    record.get("type", ""),
                    record.get("identifier", ""),
                    record.get("context", ""),
                    note_preview
                )
            )

        if show_status:
            self.queue_note_status_label.config(
                text="Note saved"
            )
            self.root.after(
                1800,
                lambda: self.queue_note_status_label.config(
                    text=""
                )
            )

        return True

    def save_investigation_queue_note(self):
        if self.current_queue_index is None:
            messagebox.showinfo(
                "Select an Item",
                "Select a queued item before saving a note."
            )
            return

        self.persist_current_queue_note(
            show_status=True
        )

    def auto_save_investigation_queue_note(
        self,
        event=None
    ):
        self.persist_current_queue_note(
            show_status=False
        )

    def remove_selected_queue_item(self):
        self.persist_current_queue_note(
            show_status=False
        )

        selection = self.investigation_queue_tree.selection()

        if not selection:
            return

        try:
            index = int(selection[0])
        except Exception:
            return

        if not (
            0 <= index
            < len(self.investigation_queue_records)
        ):
            return

        self.investigation_queue_records.pop(
            index
        )

        next_index = None

        if self.investigation_queue_records:
            next_index = min(
                index,
                len(
                    self.investigation_queue_records
                ) - 1
            )

        self.refresh_investigation_queue(
            select_index=next_index
        )

    def clear_investigation_queue(self):
        if not self.investigation_queue_records:
            return

        confirmed = messagebox.askyesno(
            "Clear Investigation Queue",
            "Remove all queued investigation items and analyst notes?"
        )

        if not confirmed:
            return

        self.investigation_queue_records = []
        self.current_queue_index = None
        self.refresh_investigation_queue()

    def open_selected_queue_item(self):
        self.persist_current_queue_note(
            show_status=False
        )

        selection = self.investigation_queue_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select an Item",
                "Select an investigation queue item first."
            )
            return

        try:
            index = int(selection[0])
        except Exception:
            return

        if not (
            0 <= index
            < len(self.investigation_queue_records)
        ):
            return

        record = self.investigation_queue_records[
            index
        ]

        item_type = record.get(
            "type",
            ""
        ).lower()

        identifier = record.get(
            "identifier"
        )
        payload = record.get(
            "payload",
            {}
        )

        if item_type == "finding":
            self.open_finding_by_id(
                identifier
            )
        elif item_type == "host":
            self.open_host_by_ip(
                identifier
            )
        elif item_type == "packet":
            self.open_packet_on_timeline(
                payload
            )

    def export_investigation_queue(self):
        self.persist_current_queue_note(
            show_status=False
        )

        if not self.investigation_queue_records:
            messagebox.showinfo(
                "Queue Empty",
                "Add investigation items before exporting the queue."
            )
            return

        capture_name = (
            self.selected_file.stem
            if self.selected_file
            else "pcap"
        )

        default_name = (
            f"{capture_name}_investigation_queue.json"
        )

        export_path = filedialog.asksaveasfilename(
            title="Export Investigation Queue",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[
                ("JSON Files", "*.json"),
                ("All Files", "*.*")
            ]
        )

        if not export_path:
            return

        export_items = []

        for record in self.investigation_queue_records:
            payload = record.get(
                "payload",
                {}
            )

            export_items.append({
                "type": record.get("type"),
                "identifier": record.get(
                    "identifier"
                ),
                "context": record.get(
                    "context"
                ),
                "analyst_note": record.get(
                    "note",
                    ""
                ),
                "payload": payload
            })

        export_data = {
            "capture": (
                str(self.selected_file)
                if self.selected_file
                else None
            ),
            "item_count": len(
                export_items
            ),
            "items": export_items
        }

        try:
            with open(
                export_path,
                "w",
                encoding="utf-8"
            ) as export_file:
                json.dump(
                    export_data,
                    export_file,
                    indent=2,
                    default=str
                )
        except Exception as error:
            messagebox.showerror(
                "Export Failed",
                f"Could not export the investigation queue.\n\n{error}"
            )
            return

        messagebox.showinfo(
            "Queue Exported",
            (
                "Investigation queue exported successfully.\n\n"
                f"{export_path}"
            )
        )

    def add_current_finding_to_queue(self):
        finding = getattr(
            self,
            "current_finding",
            None
        )

        if not finding:
            return

        finding_id = finding.get(
            "finding_id",
            "UNKNOWN"
        )

        context = (
            f"{finding.get('risk_score', 0)}/100 "
            f"{finding.get('assessment', 'UNKNOWN')}"
        )

        self.add_to_investigation_queue(
            "Finding",
            finding_id,
            context,
            finding
        )

    def add_current_host_to_queue(self):
        host = getattr(
            self,
            "current_host",
            None
        )

        if not host:
            return

        ip = host.get(
            "ip",
            "Unknown"
        )

        context = (
            f"{host.get('risk_score', 0)}/100 "
            f"{host.get('assessment', 'UNKNOWN')}"
        )

        self.add_to_investigation_queue(
            "Host",
            ip,
            context,
            host
        )

    def add_selected_packet_evidence_to_queue(self):
        packet = getattr(
            self,
            "selected_packet_evidence",
            None
        )

        if not packet:
            selection = self.packet_evidence_tree.selection()

            if not selection:
                messagebox.showinfo(
                    "Select a Packet",
                    "Click the exact packet row you want to queue first."
                )
                return

            try:
                index = int(selection[0])
                packet = self.packet_evidence_records[
                    index
                ]
            except Exception:
                return

        packet_number = packet.get(
            "packet_number",
            "?"
        )

        finding_id = (
            self.current_finding.get(
                "finding_id",
                "Finding"
            )
            if getattr(
                self,
                "current_finding",
                None
            )
            else "Finding"
        )

        self.add_to_investigation_queue(
            "Packet",
            f"Packet {packet_number}",
            f"{finding_id} evidence",
            packet
        )

    def add_selected_threat_hunt_host_to_queue(self):
        selection = self.threat_hunt_host_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a Host",
                "Select a Threat Hunt host first."
            )
            return

        try:
            index = int(selection[0])
            host = self.threat_hunt_host_records[
                index
            ]
        except Exception:
            return

        self.add_to_investigation_queue(
            "Host",
            host.get("ip", "Unknown"),
            (
                f"{host.get('risk_score', 0)}/100 "
                f"{host.get('assessment', 'UNKNOWN')}"
            ),
            host
        )

    def add_selected_threat_hunt_finding_to_queue(self):
        selection = self.threat_hunt_finding_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a Finding",
                "Select a Threat Hunt finding first."
            )
            return

        try:
            index = int(selection[0])
            finding = self.threat_hunt_finding_records[
                index
            ]
        except Exception:
            return

        self.add_to_investigation_queue(
            "Finding",
            finding.get(
                "finding_id",
                "UNKNOWN"
            ),
            (
                f"{finding.get('risk_score', 0)}/100 "
                f"{finding.get('assessment', 'UNKNOWN')}"
            ),
            finding
        )

    def add_selected_threat_hunt_packet_to_queue(self):
        packet = getattr(
            self,
            "selected_threat_hunt_packet",
            None
        )

        if not packet:
            selection = self.threat_hunt_packet_tree.selection()

            if not selection:
                messagebox.showinfo(
                    "Select a Packet",
                    "Click the exact Threat Hunt packet row you want to queue first."
                )
                return

            try:
                index = int(selection[0])
                packet = self.threat_hunt_packet_records[
                    index
                ]
            except Exception:
                return

        packet_number = packet.get(
            "packet_number",
            "?"
        )

        finding_ids = packet.get(
            "finding_ids",
            []
        )

        context = (
            ", ".join(finding_ids)
            if finding_ids
            else "Threat Hunt evidence"
        )

        self.add_to_investigation_queue(
            "Packet",
            f"Packet {packet_number}",
            context,
            packet
        )

    def create_finding_investigation_tab(self):
        frame = ttk.Frame(
            self.notebook,
            style="Card.TFrame"
        )

        self.notebook.add(
            frame,
            text="Finding Investigation"
        )

        container = ttk.Frame(
            frame,
            style="Card.TFrame",
            padding=10
        )
        container.pack(fill="both", expand=True)

        # ----------------------------------------------------------
        # LEFT PANEL: FINDING LIST + FILTERS
        # ----------------------------------------------------------
        left_panel = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        left_panel.pack(
            side="left",
            fill="both",
            padx=(0, 10)
        )

        left_header = ttk.Frame(
            left_panel,
            style="Card.TFrame"
        )
        left_header.pack(fill="x", pady=(0, 8))

        ttk.Label(
            left_header,
            text="Security Findings",
            style="Body.TLabel"
        ).pack(side="left")

        self.finding_count_label = ttk.Label(
            left_header,
            text="0 findings",
            style="CardMuted.TLabel"
        )
        self.finding_count_label.pack(side="right")

        search_frame = ttk.Frame(
            left_panel,
            style="Card.TFrame"
        )
        search_frame.pack(fill="x", pady=(0, 7))

        self.finding_search_var = tk.StringVar()

        self.finding_search_entry = tk.Entry(
            search_frame,
            textvariable=self.finding_search_var,
            font=("Segoe UI", 9),
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#374151",
            highlightcolor="#60a5fa"
        )
        self.finding_search_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=5
        )

        self.finding_search_var.trace_add(
            "write",
            self.refresh_finding_list
        )

        self.review_only_var = tk.BooleanVar(value=False)

        self.review_only_checkbox = ttk.Checkbutton(
            search_frame,
            text="Review priority",
            variable=self.review_only_var,
            command=self.refresh_finding_list,
            style="Option.TCheckbutton"
        )
        self.review_only_checkbox.pack(
            side="left",
            padx=(8, 0)
        )

        tree_frame = ttk.Frame(
            left_panel,
            style="Card.TFrame"
        )
        tree_frame.pack(fill="both", expand=True)

        finding_scrollbar = ttk.Scrollbar(
            tree_frame,
            orient="vertical"
        )
        finding_scrollbar.pack(
            side="right",
            fill="y"
        )

        self.finding_tree = ttk.Treeview(
            tree_frame,
            columns=(
                "id",
                "risk",
                "type",
                "source"
            ),
            show="headings",
            height=12,
            yscrollcommand=finding_scrollbar.set
        )
        self.finding_tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        finding_scrollbar.config(
            command=self.finding_tree.yview
        )

        self.finding_tree.heading(
            "id",
            text="ID"
        )
        self.finding_tree.heading(
            "risk",
            text="Risk"
        )
        self.finding_tree.heading(
            "type",
            text="Finding Type"
        )
        self.finding_tree.heading(
            "source",
            text="Source / Scope"
        )

        self.finding_tree.column(
            "id",
            width=108,
            minwidth=96,
            anchor="center",
            stretch=False
        )
        self.finding_tree.column(
            "risk",
            width=66,
            minwidth=58,
            anchor="center",
            stretch=False
        )
        self.finding_tree.column(
            "type",
            width=230,
            minwidth=175,
            anchor="w",
            stretch=True
        )
        self.finding_tree.column(
            "source",
            width=165,
            minwidth=130,
            anchor="w",
            stretch=True
        )

        self.finding_tree.bind(
            "<<TreeviewSelect>>",
            self.on_finding_selected
        )

        # ----------------------------------------------------------
        # RIGHT PANEL: SELECTED FINDING DETAILS
        # ----------------------------------------------------------
        right_panel = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        right_panel.pack(
            side="left",
            fill="both",
            expand=True
        )

        finding_summary_bar = ttk.Frame(
            right_panel,
            style="Card.TFrame"
        )
        finding_summary_bar.pack(
            fill="x",
            pady=(0, 8)
        )

        self.selected_finding_label = ttk.Label(
            finding_summary_bar,
            text="Select a finding",
            style="Body.TLabel"
        )
        self.selected_finding_label.pack(
            side="left"
        )

        self.selected_finding_risk_label = ttk.Label(
            finding_summary_bar,
            text="-- / 100",
            style="CardMuted.TLabel"
        )
        self.selected_finding_risk_label.pack(
            side="right"
        )

        link_bar = ttk.Frame(
            right_panel,
            style="Card.TFrame"
        )
        link_bar.pack(
            fill="x",
            pady=(0, 8)
        )

        self.related_host_var = tk.StringVar()

        self.related_host_combo = ttk.Combobox(
            link_bar,
            textvariable=self.related_host_var,
            state="readonly",
            width=42
        )
        self.related_host_combo.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.open_related_host_button = ttk.Button(
            link_bar,
            text="Open Related Host",
            command=self.open_related_host,
            state="disabled",
            style="Secondary.TButton"
        )
        self.open_related_host_button.pack(
            side="left",
            padx=(8, 0)
        )

        self.add_finding_queue_button = ttk.Button(
            link_bar,
            text="Add Finding to Queue",
            command=self.add_current_finding_to_queue,
            state="disabled",
            style="Secondary.TButton"
        )
        self.add_finding_queue_button.pack(
            side="left",
            padx=(8, 0)
        )

        self.finding_detail_notebook = ttk.Notebook(
            right_panel
        )
        self.finding_detail_notebook.pack(
            fill="both",
            expand=True
        )

        finding_details_frame = ttk.Frame(
            self.finding_detail_notebook,
            style="Card.TFrame"
        )
        self.finding_detail_notebook.add(
            finding_details_frame,
            text="Finding Details"
        )

        detail_scrollbar = ttk.Scrollbar(
            finding_details_frame,
            orient="vertical"
        )
        detail_scrollbar.pack(
            side="right",
            fill="y"
        )

        self.finding_detail_text = tk.Text(
            finding_details_frame,
            wrap="word",
            font=("Consolas", 10),
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=14,
            pady=12,
            yscrollcommand=detail_scrollbar.set,
            state="disabled"
        )
        self.finding_detail_text.pack(
            side="left",
            fill="both",
            expand=True
        )

        detail_scrollbar.config(
            command=self.finding_detail_text.yview
        )

        self.packet_evidence_frame = ttk.Frame(
            self.finding_detail_notebook,
            style="Card.TFrame"
        )
        self.finding_detail_notebook.add(
            self.packet_evidence_frame,
            text="Packet Evidence (0)"
        )

        packet_header = ttk.Frame(
            self.packet_evidence_frame,
            style="Card.TFrame",
            padding=(8, 8, 8, 4)
        )
        packet_header.pack(fill="x")

        self.packet_evidence_summary_label = ttk.Label(
            packet_header,
            text=(
                "Representative metadata only. "
                "Packet payloads are not displayed."
            ),
            style="CardMuted.TLabel"
        )
        self.packet_evidence_summary_label.pack(
            anchor="w"
        )

        packet_header_actions = ttk.Frame(
            packet_header,
            style="Card.TFrame"
        )
        packet_header_actions.pack(
            fill="x",
            pady=(6, 0)
        )

        ttk.Button(
            packet_header_actions,
            text="Show on Timeline",
            command=self.open_selected_packet_evidence_on_timeline,
            style="Secondary.TButton"
        ).pack(side="left")

        ttk.Button(
            packet_header_actions,
            text="Add Selected to Queue",
            command=self.add_selected_packet_evidence_to_queue,
            style="Secondary.TButton"
        ).pack(
            side="left",
            padx=(8, 0)
        )

        packet_table_frame = ttk.Frame(
            self.packet_evidence_frame,
            style="Card.TFrame",
            padding=(8, 4, 8, 4)
        )
        packet_table_frame.pack(
            fill="both",
            expand=True
        )

        packet_y_scrollbar = ttk.Scrollbar(
            packet_table_frame,
            orient="vertical"
        )
        packet_y_scrollbar.pack(
            side="right",
            fill="y"
        )

        packet_x_scrollbar = ttk.Scrollbar(
            packet_table_frame,
            orient="horizontal"
        )
        packet_x_scrollbar.pack(
            side="bottom",
            fill="x"
        )

        self.packet_evidence_tree = ttk.Treeview(
            packet_table_frame,
            columns=(
                "packet",
                "time",
                "source",
                "destination",
                "protocol",
                "ports",
                "bytes"
            ),
            show="headings",
            height=7,
            yscrollcommand=packet_y_scrollbar.set,
            xscrollcommand=packet_x_scrollbar.set
        )
        self.packet_evidence_tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        packet_y_scrollbar.config(
            command=self.packet_evidence_tree.yview
        )
        packet_x_scrollbar.config(
            command=self.packet_evidence_tree.xview
        )

        packet_columns = {
            "packet": ("Packet", 74, "center"),
            "time": ("Time Offset", 105, "center"),
            "source": ("Source", 175, "w"),
            "destination": ("Destination", 175, "w"),
            "protocol": ("Protocol", 80, "center"),
            "ports": ("Ports", 125, "center"),
            "bytes": ("Bytes", 70, "center")
        }

        for column, (
            heading,
            width,
            anchor
        ) in packet_columns.items():
            self.packet_evidence_tree.heading(
                column,
                text=heading
            )
            self.packet_evidence_tree.column(
                column,
                width=width,
                minwidth=60,
                anchor=anchor,
                stretch=(
                    column
                    in {"source", "destination"}
                )
            )

        self.packet_evidence_tree.bind(
            "<<TreeviewSelect>>",
            self.on_packet_evidence_selected
        )

        packet_detail_frame = ttk.Frame(
            self.packet_evidence_frame,
            style="Card.TFrame",
            padding=(8, 4, 8, 8)
        )
        packet_detail_frame.pack(fill="x")

        self.packet_detail_text = tk.Text(
            packet_detail_frame,
            height=5,
            wrap="word",
            font=("Consolas", 9),
            bg="#111827",
            fg="#d1d5db",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=10,
            pady=8,
            state="disabled"
        )
        self.packet_detail_text.pack(fill="x")

        self.packet_evidence_tree.bind(
            "<Double-1>",
            lambda event: self.open_selected_packet_evidence_on_timeline()
        )

        self.packet_evidence_records = []
        self.selected_packet_evidence = None

        self.visual_report = None
        self.visual_hover_items = []
        self.timeline_packet_marker = None

        if hasattr(self, "visual_summary_label"):
            self.visual_summary_label.config(
                text="No visualization data"
            )

        if hasattr(self, "visual_canvas"):
            self.visual_canvas.delete("all")
            self.draw_visual_empty_state(
                "Analyze a PCAP to display visual data.",
                max(
                    self.visual_canvas.winfo_width(),
                    500
                ),
                max(
                    self.visual_canvas.winfo_height(),
                    250
                )
            )

        self.finding_records = []
        self.filtered_finding_records = []
        self.current_finding = None
        self.related_host_lookup = {}

        return frame

    def display_findings(self, report):
        investigation = report.get(
            "finding_investigation",
            {}
        )

        self.finding_records = list(
            investigation.get("findings", [])
        )

        self.finding_search_var.set("")
        self.review_only_var.set(False)

        self.refresh_finding_list()

    def refresh_finding_list(self, *args):
        if not hasattr(self, "finding_tree"):
            return

        search_text = (
            self.finding_search_var.get()
            .strip()
            .lower()
        )

        review_only = self.review_only_var.get()

        filtered = []

        for finding in self.finding_records:
            related_ips = " ".join(
                str(item.get("ip", ""))
                for item in finding.get(
                    "related_hosts",
                    []
                )
            )

            searchable = " ".join([
                str(finding.get("finding_id", "")),
                str(finding.get("type", "")),
                str(finding.get("title", "")),
                str(finding.get("assessment", "")),
                str(finding.get("source", "")),
                str(finding.get("target", "")),
                related_ips
            ]).lower()

            if (
                search_text
                and search_text not in searchable
            ):
                continue

            if (
                review_only
                and finding.get("risk_score", 0) < 25
            ):
                continue

            filtered.append(finding)

        self.filtered_finding_records = filtered

        for item in self.finding_tree.get_children():
            self.finding_tree.delete(item)

        for index, finding in enumerate(filtered):
            score = finding.get("risk_score", 0)
            assessment = finding.get(
                "assessment",
                "LIKELY NORMAL"
            )

            source = finding.get("source")

            if not source:
                source = "Capture-level"

            tag = self.get_host_tree_tag(
                assessment,
                score
            )

            self.finding_tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    finding.get(
                        "finding_id",
                        "UNKNOWN"
                    ),
                    f"{score}/100",
                    finding.get(
                        "type",
                        "UNKNOWN"
                    ),
                    source
                ),
                tags=(tag,)
            )

        self.finding_tree.tag_configure(
            "high",
            foreground="#f87171"
        )
        self.finding_tree.tag_configure(
            "suspicious",
            foreground="#fbbf24"
        )
        self.finding_tree.tag_configure(
            "review",
            foreground="#facc15"
        )
        self.finding_tree.tag_configure(
            "normal",
            foreground="#d1d5db"
        )

        total = len(self.finding_records)
        shown = len(filtered)

        if total == shown:
            count_text = (
                f"{total:,} finding"
                if total == 1
                else f"{total:,} findings"
            )
        else:
            count_text = f"{shown:,} of {total:,}"

        self.finding_count_label.config(
            text=count_text
        )

        if filtered:
            first_item = (
                self.finding_tree.get_children()[0]
            )

            self.finding_tree.selection_set(
                first_item
            )
            self.finding_tree.focus(
                first_item
            )
            self.finding_tree.see(
                first_item
            )

            self.show_finding_details(
                filtered[0]
            )
        else:
            self.current_finding = None

            self.selected_finding_label.config(
                text="No matching findings"
            )
            self.selected_finding_risk_label.config(
                text="-- / 100",
                foreground="#9ca3af"
            )

            self.related_host_combo[
                "values"
            ] = []
            self.related_host_var.set("")

            self.open_related_host_button.config(
                state="disabled"
            )

            if total == 0:
                message = (
                    "No structured security findings were "
                    "produced for this capture."
                )
            else:
                message = (
                    "No findings match the current filter."
                )

            self.set_text(
                self.finding_detail_text,
                message
            )

            self.packet_evidence_records = []

            if hasattr(
                self,
                "packet_evidence_tree"
            ):
                for item in self.packet_evidence_tree.get_children():
                    self.packet_evidence_tree.delete(item)

            if hasattr(
                self,
                "finding_detail_notebook"
            ):
                self.finding_detail_notebook.tab(
                    self.packet_evidence_frame,
                    text="Packet Evidence (0)"
                )

            if hasattr(
                self,
                "packet_detail_text"
            ):
                self.set_text(
                    self.packet_detail_text,
                    "No packet evidence available."
                )

    def on_finding_selected(self, event=None):
        selection = self.finding_tree.selection()

        if not selection:
            return

        try:
            index = int(selection[0])
        except Exception:
            return

        if index >= len(
            self.filtered_finding_records
        ):
            return

        self.show_finding_details(
            self.filtered_finding_records[index]
        )

    def format_duration(self, seconds):
        try:
            seconds = float(seconds)
        except Exception:
            return "Unknown"

        if seconds < 60:
            return f"{seconds:.2f} seconds"

        if seconds < 3600:
            minutes = int(seconds // 60)
            remaining = seconds % 60
            return (
                f"{minutes}m {remaining:.2f}s"
            )

        hours = int(seconds // 3600)
        remaining = seconds % 3600
        minutes = int(remaining // 60)
        seconds_left = remaining % 60

        return (
            f"{hours}h {minutes}m "
            f"{seconds_left:.2f}s"
        )

    def show_finding_details(self, finding):
        self.current_finding = finding

        finding_id = finding.get(
            "finding_id",
            "UNKNOWN"
        )
        title = finding.get(
            "title",
            finding.get("type", "Finding")
        )
        score = finding.get(
            "risk_score",
            0
        )
        assessment = finding.get(
            "assessment",
            "LIKELY NORMAL"
        )
        confidence = finding.get(
            "confidence"
        )

        risk_color = self.get_assessment_color(
            assessment
        )

        self.selected_finding_label.config(
            text=f"{finding_id}  •  {title}"
        )
        self.selected_finding_risk_label.config(
            text=(
                f"{score} / 100  •  "
                f"{assessment}"
            ),
            foreground=risk_color
        )

        if hasattr(self, "add_finding_queue_button"):
            self.add_finding_queue_button.config(
                state="normal"
            )

        related_hosts = finding.get(
            "related_hosts",
            []
        )

        self.related_host_lookup = {}

        host_choices = []

        for item in related_hosts:
            ip = item.get("ip")

            if not ip:
                continue

            role = item.get(
                "role",
                "RELATED"
            )

            label = f"{ip}  •  {role}"

            host_choices.append(label)
            self.related_host_lookup[label] = ip

        self.related_host_combo[
            "values"
        ] = host_choices

        if host_choices:
            self.related_host_var.set(
                host_choices[0]
            )
            self.open_related_host_button.config(
                state="normal"
            )
        else:
            self.related_host_var.set("")
            self.open_related_host_button.config(
                state="disabled"
            )

        timing = finding.get(
            "timing",
            {}
        )

        first_seen = timing.get(
            "first_seen_utc"
        ) or "Unknown"

        last_seen = timing.get(
            "last_seen_utc"
        ) or "Unknown"

        duration = self.format_duration(
            timing.get(
                "duration_seconds",
                0
            )
        )

        source = finding.get(
            "source"
        ) or "Capture-level / not attributed"

        target = finding.get(
            "target"
        ) or "Not specified"

        destination_port = finding.get(
            "destination_port"
        )

        if destination_port is None:
            destination_port = "Not specified"

        protocol = finding.get(
            "protocol"
        ) or "Unknown"

        lines = [
            "FINDING INVESTIGATION",
            "=" * 76,
            "",
            "FINDING SUMMARY",
            "-" * 76,
            f"Finding ID:              {finding_id}",
            f"Type:                    {finding.get('type', 'UNKNOWN')}",
            f"Title:                   {title}",
            f"Risk Score:              {score}/100",
            f"Assessment:              {assessment}",
            (
                f"Confidence:              "
                f"{confidence if confidence else 'Not assigned'}"
            ),
            "",
            "NETWORK CONTEXT",
            "-" * 76,
            f"Source / Scope:          {source}",
            f"Target:                  {target}",
            f"Protocol:                {protocol}",
            f"Destination Port:        {destination_port}",
            "",
            "TIMING",
            "-" * 76,
            f"First Seen (UTC):        {first_seen}",
            f"Last Seen (UTC):         {last_seen}",
            f"Observed Duration:       {duration}",
            "",
            "SUMMARY",
            "-" * 76,
            finding.get(
                "summary",
                "No summary available."
            ),
            "",
            "EVIDENCE",
            "-" * 76
        ]

        evidence = finding.get(
            "evidence",
            []
        )

        if evidence:
            for item in evidence:
                name = str(
                    item.get(
                        "name",
                        "Evidence"
                    )
                )
                value = item.get(
                    "value",
                    "Unknown"
                )

                lines.append(
                    f"  • {name}: {value}"
                )
        else:
            lines.append(
                "  No structured evidence available"
            )

        lines.extend([
            "",
            "DETECTION INDICATORS",
            "-" * 76
        ])

        indicators = finding.get(
            "indicators",
            []
        )

        if indicators:
            for indicator in indicators:
                lines.append(
                    f"  • {indicator}"
                )
        else:
            lines.append(
                "  No indicators available"
            )

        lines.extend([
            "",
            "RELATED HOSTS",
            "-" * 76
        ])

        if related_hosts:
            for host in related_hosts:
                lines.append(
                    f"  • {host.get('ip', 'Unknown')} "
                    f"({host.get('role', 'RELATED')})"
                )
        else:
            lines.append(
                "  No directly related hosts recorded"
            )

        details = finding.get(
            "details",
            {}
        )

        lines.extend([
            "",
            "TYPE-SPECIFIC DETAILS",
            "-" * 76
        ])

        if details:
            for key, value in details.items():
                label = (
                    key.replace("_", " ")
                    .strip()
                    .title()
                )

                if isinstance(value, list):
                    lines.append(
                        f"{label}:"
                    )

                    if value:
                        for item in value[:20]:
                            if isinstance(item, dict):
                                item_text = ", ".join(
                                    f"{k.replace('_', ' ').title()}: {v}"
                                    for k, v in item.items()
                                )
                                lines.append(
                                    f"  • {item_text}"
                                )
                            else:
                                lines.append(
                                    f"  • {item}"
                                )

                        if len(value) > 20:
                            lines.append(
                                f"  ... {len(value) - 20} "
                                "additional item(s)"
                            )
                    else:
                        lines.append(
                            "  None"
                        )

                elif isinstance(value, dict):
                    lines.append(
                        f"{label}:"
                    )

                    if value:
                        for sub_key, sub_value in value.items():
                            sub_label = (
                                str(sub_key)
                                .replace("_", " ")
                                .title()
                            )

                            lines.append(
                                f"  • {sub_label}: "
                                f"{sub_value}"
                            )
                    else:
                        lines.append(
                            "  None"
                        )
                else:
                    lines.append(
                        f"{label}: {value}"
                    )
        else:
            lines.append(
                "No additional type-specific details available."
            )

        lines.extend([
            "",
            "DEFENSIVE ANALYST NOTE",
            "-" * 76,
            finding.get(
                "defensive_note",
                (
                    "This finding is behavioral evidence for "
                    "defensive review and is not proof of compromise."
                )
            )
        ])

        self.set_text(
            self.finding_detail_text,
            "\n".join(lines)
        )

        self.display_packet_evidence(
            finding
        )

    def display_packet_evidence(self, finding):
        samples = list(
            finding.get(
                "packet_evidence",
                []
            )
        )

        self.packet_evidence_records = samples

        for item in self.packet_evidence_tree.get_children():
            self.packet_evidence_tree.delete(item)

        sample_count = len(samples)

        self.finding_detail_notebook.tab(
            self.packet_evidence_frame,
            text=f"Packet Evidence ({sample_count})"
        )

        self.packet_evidence_summary_label.config(
            text=(
                f"{sample_count} representative packet "
                f"{'sample' if sample_count == 1 else 'samples'} "
                "• metadata only • no payload content"
            )
        )

        if not samples:
            self.selected_packet_evidence = None

            self.set_text(
                self.packet_detail_text,
                (
                    "No representative packet metadata was retained "
                    "for this finding. The structured evidence remains "
                    "available in Finding Details."
                )
            )
            return

        for index, packet in enumerate(samples):
            source_port = packet.get(
                "source_port"
            )
            destination_port = packet.get(
                "destination_port"
            )

            if (
                source_port is not None
                or destination_port is not None
            ):
                ports = (
                    f"{source_port if source_port is not None else '-'}"
                    f" → "
                    f"{destination_port if destination_port is not None else '-'}"
                )
            else:
                ports = "-"

            offset = packet.get(
                "offset_seconds"
            )

            if offset is None:
                time_text = "Unknown"
            else:
                time_text = self.format_duration(
                    offset
                )

            self.packet_evidence_tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    packet.get(
                        "packet_number",
                        "?"
                    ),
                    time_text,
                    packet.get(
                        "source",
                        "Unknown"
                    ),
                    packet.get(
                        "destination",
                        "Unknown"
                    ),
                    packet.get(
                        "protocol",
                        "Unknown"
                    ),
                    ports,
                    packet.get(
                        "length_bytes",
                        0
                    )
                )
            )

        first_item = (
            self.packet_evidence_tree.get_children()[0]
        )

        self.packet_evidence_tree.selection_set(
            first_item
        )
        self.packet_evidence_tree.focus(
            first_item
        )
        self.packet_evidence_tree.see(
            first_item
        )

        self.selected_packet_evidence = samples[0]

        self.show_packet_evidence_details(
            samples[0]
        )

    def on_packet_evidence_selected(self, event=None):
        selection = self.packet_evidence_tree.selection()

        if not selection:
            self.selected_packet_evidence = None
            return

        try:
            index = int(selection[0])
        except Exception:
            self.selected_packet_evidence = None
            return

        if index >= len(
            self.packet_evidence_records
        ):
            self.selected_packet_evidence = None
            return

        packet = self.packet_evidence_records[
            index
        ]

        self.selected_packet_evidence = packet

        self.show_packet_evidence_details(
            packet
        )

    def show_packet_evidence_details(self, packet):
        source_port = packet.get(
            "source_port"
        )
        destination_port = packet.get(
            "destination_port"
        )

        timestamp_utc = packet.get(
            "timestamp_utc"
        ) or "Unknown"

        offset = packet.get(
            "offset_seconds"
        )

        if offset is None:
            offset_text = "Unknown"
        else:
            offset_text = self.format_duration(
                offset
            )

        tcp_flags = packet.get(
            "tcp_flags"
        ) or "N/A"

        dns_query = packet.get(
            "dns_query"
        ) or "N/A"

        relevance = packet.get(
            "relevance"
        ) or (
            "Representative packet metadata associated "
            "with this finding."
        )

        lines = [
            "SELECTED PACKET METADATA",
            "=" * 70,
            f"Packet Number:           {packet.get('packet_number', 'Unknown')}",
            f"Timestamp (UTC):         {timestamp_utc}",
            f"Capture Offset:          {offset_text}",
            f"Source:                  {packet.get('source', 'Unknown')}",
            f"Destination:             {packet.get('destination', 'Unknown')}",
            f"Protocol:                {packet.get('protocol', 'Unknown')}",
            f"Source Port:             {source_port if source_port is not None else 'N/A'}",
            f"Destination Port:        {destination_port if destination_port is not None else 'N/A'}",
            f"Packet Length:           {packet.get('length_bytes', 0):,} bytes",
            f"TCP Flags:               {tcp_flags}",
            f"DNS Query:               {dns_query}",
            "",
            "Why this sample is relevant:",
            f"  {relevance}",
            "",
            (
                "Note: This view shows packet metadata only. "
                "Packet payload content is not displayed."
            )
        ]

        self.set_text(
            self.packet_detail_text,
            "\n".join(lines)
        )

    def open_selected_packet_evidence_on_timeline(self):
        selection = self.packet_evidence_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a Packet",
                "Select a packet evidence row first."
            )
            return

        try:
            index = int(selection[0])
            packet = self.packet_evidence_records[index]
        except Exception:
            return

        self.open_packet_on_timeline(packet)

    def on_threat_hunt_packet_selected(
        self,
        event=None
    ):
        selection = self.threat_hunt_packet_tree.selection()

        if not selection:
            self.selected_threat_hunt_packet = None
            return

        try:
            index = int(selection[0])
            self.selected_threat_hunt_packet = (
                self.threat_hunt_packet_records[index]
            )
        except Exception:
            self.selected_threat_hunt_packet = None

    def open_selected_threat_hunt_packet_on_timeline(self):
        selection = self.threat_hunt_packet_tree.selection()

        if not selection:
            messagebox.showinfo(
                "Select a Packet",
                "Select a Threat Hunt packet result first."
            )
            return

        try:
            index = int(selection[0])
            packet = self.threat_hunt_packet_records[index]
        except Exception:
            return

        self.open_packet_on_timeline(packet)

    def open_packet_on_timeline(self, packet):
        if not packet:
            return

        offset = packet.get(
            "offset_seconds"
        )

        if not isinstance(
            offset,
            (int, float)
        ):
            messagebox.showinfo(
                "Timeline Position Unavailable",
                (
                    "This representative packet does not have a capture "
                    "offset that can be shown on the timeline."
                )
            )
            return

        self.timeline_packet_marker = {
            "packet_number": packet.get(
                "packet_number",
                "?"
            ),
            "offset_seconds": float(offset),
            "source": packet.get(
                "source",
                "Unknown"
            ),
            "destination": packet.get(
                "destination",
                "Unknown"
            ),
            "protocol": packet.get(
                "protocol",
                "Unknown"
            )
        }

        self.chart_type_var.set(
            "Traffic Timeline"
        )

        self.notebook.select(
            self.visual_tab
        )

        self.visual_hint_label.config(
            text=(
                f"Packet {self.timeline_packet_marker['packet_number']} "
                f"highlighted at {self.format_duration(offset)}. "
                "Hover to inspect findings, hosts, and traffic."
            )
        )

        self.redraw_visual_chart()

    def open_finding_by_id(self, finding_id):
        if not finding_id:
            return

        if not hasattr(self, "finding_tree"):
            return

        # Clear filters so the requested finding is guaranteed visible.
        self.finding_search_var.set("")
        self.review_only_var.set(False)

        self.refresh_finding_list()

        matching_index = None

        for index, finding in enumerate(
            self.filtered_finding_records
        ):
            if (
                str(
                    finding.get(
                        "finding_id",
                        ""
                    )
                )
                == str(finding_id)
            ):
                matching_index = index
                break

        if matching_index is None:
            messagebox.showinfo(
                "Finding Not Found",
                (
                    f"{finding_id} is not available in the "
                    "current structured finding set."
                )
            )
            return

        item_id = str(matching_index)

        if not self.finding_tree.exists(item_id):
            return

        self.finding_tree.selection_set(
            item_id
        )
        self.finding_tree.focus(
            item_id
        )
        self.finding_tree.see(
            item_id
        )

        self.show_finding_details(
            self.filtered_finding_records[
                matching_index
            ]
        )

        self.notebook.select(
            self.finding_tab
        )

    def open_related_host(self):
        selection = self.related_host_var.get()

        if not selection:
            return

        ip = self.related_host_lookup.get(
            selection
        )

        if not ip:
            return

        self.open_host_by_ip(ip)

    def open_host_by_ip(self, ip):
        if not hasattr(self, "host_tree"):
            return

        # Remove host filters so the linked host is visible.
        self.host_search_var.set("")
        self.flagged_only_var.set(False)

        self.refresh_host_list()

        matching_index = None

        for index, host in enumerate(
            self.filtered_host_records
        ):
            if str(host.get("ip")) == str(ip):
                matching_index = index
                break

        if matching_index is None:
            messagebox.showinfo(
                "Host Not Found",
                (
                    f"{ip} is related to this finding, "
                    "but no host summary is available "
                    "for it in the current capture."
                )
            )
            return

        item_id = str(matching_index)

        if not self.host_tree.exists(item_id):
            return

        self.host_tree.selection_set(
            item_id
        )
        self.host_tree.focus(
            item_id
        )
        self.host_tree.see(
            item_id
        )

        self.show_host_details(
            self.filtered_host_records[
                matching_index
            ]
        )

        self.notebook.select(
            self.host_tab
        )

    def create_visual_analysis_tab(self):
        frame = ttk.Frame(
            self.notebook,
            style="Card.TFrame"
        )
        self.notebook.add(
            frame,
            text="Visual Analysis"
        )

        container = ttk.Frame(
            frame,
            style="Card.TFrame",
            padding=10
        )
        container.pack(fill="both", expand=True)

        header = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        header.pack(fill="x", pady=(0, 8))

        ttk.Label(
            header,
            text="Visual Network Analysis",
            style="Body.TLabel"
        ).pack(side="left")

        self.visual_summary_label = ttk.Label(
            header,
            text="No visualization data",
            style="CardMuted.TLabel"
        )
        self.visual_summary_label.pack(side="right")

        controls = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        controls.pack(fill="x", pady=(0, 8))

        ttk.Label(
            controls,
            text="View:",
            style="Body.TLabel"
        ).pack(side="left", padx=(0, 7))

        self.chart_type_var = tk.StringVar(
            value="Traffic Timeline"
        )

        self.chart_selector = ttk.Combobox(
            controls,
            textvariable=self.chart_type_var,
            state="readonly",
            width=28,
            values=[
                "Traffic Timeline",
                "DNS Activity Timeline",
                "Protocol Distribution",
                "Most Active Hosts",
                "Top Destination Ports",
                "Network Relationship Map"
            ]
        )
        self.chart_selector.pack(side="left")

        self.chart_selector.bind(
            "<<ComboboxSelected>>",
            self.redraw_visual_chart
        )

        self.visual_hint_label = ttk.Label(
            controls,
            text=(
                "Hover to inspect. Click finding markers, host bars, "
                "or map nodes to drill into related evidence."
            ),
            style="CardMuted.TLabel"
        )
        self.visual_hint_label.pack(
            side="left",
            padx=(12, 0)
        )

        chart_frame = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        chart_frame.pack(fill="both", expand=True)

        self.visual_canvas = tk.Canvas(
            chart_frame,
            bg="#0f172a",
            highlightthickness=1,
            highlightbackground="#374151",
            relief="flat"
        )
        self.visual_canvas.pack(fill="both", expand=True)

        self.visual_canvas.bind(
            "<Configure>",
            self.redraw_visual_chart
        )
        self.visual_canvas.bind(
            "<Motion>",
            self.on_visual_hover
        )
        self.visual_canvas.bind(
            "<Leave>",
            self.clear_visual_tooltip
        )

        self.visual_canvas.bind(
            "<Button-1>",
            self.on_visual_click
        )

        self.visual_report = None
        self.visual_hover_items = []

        return frame

    def display_visuals(self, report):
        self.visual_report = report

        visual = report.get(
            "visual_analysis",
            {}
        )

        bucket_count = visual.get(
            "bucket_count",
            0
        )
        markers = visual.get(
            "finding_markers",
            []
        )
        duration = visual.get(
            "capture_timing",
            {}
        ).get(
            "duration_seconds",
            0
        )

        self.visual_summary_label.config(
            text=(
                f"{bucket_count} timeline buckets  •  "
                f"{len(markers)} finding markers  •  "
                f"{self.format_duration(duration)}"
            )
        )

        self.redraw_visual_chart()

    def redraw_visual_chart(self, event=None):
        if not hasattr(self, "visual_canvas"):
            return

        self.visual_canvas.delete("all")
        self.visual_hover_items = []

        width = max(
            self.visual_canvas.winfo_width(),
            500
        )
        height = max(
            self.visual_canvas.winfo_height(),
            250
        )

        if not self.visual_report:
            self.draw_visual_empty_state(
                "Analyze a PCAP to display visual data.",
                width,
                height
            )
            return

        chart_type = self.chart_type_var.get()

        if chart_type == "Traffic Timeline":
            self.draw_timeline_chart(
                "packets",
                "Traffic Volume Over Time",
                "packets",
                width,
                height,
                True
            )

        elif chart_type == "DNS Activity Timeline":
            self.draw_timeline_chart(
                "dns_queries",
                "DNS Query Activity Over Time",
                "DNS queries",
                width,
                height,
                True
            )

        elif chart_type == "Protocol Distribution":
            protocols = self.visual_report.get(
                "summary",
                {}
            ).get(
                "protocols",
                {}
            )
            items = sorted(
                protocols.items(),
                key=lambda item: item[1],
                reverse=True
            )[:10]

            self.draw_bar_chart(
                items,
                "Top Protocols",
                "packets",
                width,
                height
            )

        elif chart_type == "Most Active Hosts":
            hosts = self.visual_report.get(
                "hosts",
                []
            )

            host_activity = [
                (
                    host.get("ip", "Unknown"),
                    host.get("packets_sent", 0)
                    + host.get("packets_received", 0)
                )
                for host in hosts
            ]

            items = sorted(
                host_activity,
                key=lambda item: item[1],
                reverse=True
            )[:10]

            self.draw_bar_chart(
                items,
                "Most Active Hosts",
                "packets",
                width,
                height,
                click_action="host"
            )

        elif chart_type == "Top Destination Ports":
            ports = self.visual_report.get(
                "visual_analysis",
                {}
            ).get(
                "top_destination_ports",
                []
            )

            items = [
                (
                    f"Port {item.get('port')}",
                    item.get("packets", 0)
                )
                for item in ports
            ]

            self.draw_bar_chart(
                items,
                "Top Destination Ports",
                "packets",
                width,
                height
            )

        elif chart_type == "Network Relationship Map":
            self.draw_network_relationship_map(
                width,
                height
            )

    def draw_visual_empty_state(
        self,
        message,
        width,
        height
    ):
        self.visual_canvas.create_text(
            width / 2,
            height / 2,
            text=message,
            fill="#9ca3af",
            font=("Segoe UI", 11)
        )

    def draw_chart_title(self, title):
        self.visual_canvas.create_text(
            18,
            17,
            text=title,
            fill="#f9fafb",
            font=("Segoe UI", 11, "bold"),
            anchor="w"
        )

    def draw_timeline_chart(
        self,
        metric,
        title,
        value_label,
        width,
        height,
        include_findings=False
    ):
        visual = self.visual_report.get(
            "visual_analysis",
            {}
        )
        points = visual.get("points", [])

        if not points:
            self.draw_visual_empty_state(
                "No timeline data is available for this capture.",
                width,
                height
            )
            return

        self.draw_chart_title(title)

        left = 72
        right = width - 24
        top = 48
        bottom = height - 48
        plot_width = max(right - left, 1)
        plot_height = max(bottom - top, 1)

        values = [
            point.get(metric, 0)
            for point in points
        ]
        maximum = max(values, default=0) or 1

        for index in range(5):
            ratio = index / 4
            y = bottom - ratio * plot_height
            value = int(maximum * ratio)

            self.visual_canvas.create_line(
                left,
                y,
                right,
                y,
                fill="#243244"
            )
            self.visual_canvas.create_text(
                left - 10,
                y,
                text=f"{value:,}",
                fill="#9ca3af",
                font=("Segoe UI", 8),
                anchor="e"
            )

        self.visual_canvas.create_text(
            16,
            top - 10,
            text=value_label,
            fill="#9ca3af",
            font=("Segoe UI", 8),
            anchor="w"
        )

        duration = visual.get(
            "capture_timing",
            {}
        ).get(
            "duration_seconds",
            0
        )

        # Time-axis guides at start, 25%, 50%, 75%, and end.
        for tick_index in range(5):
            ratio = tick_index / 4
            x = left + ratio * plot_width

            self.visual_canvas.create_line(
                x,
                top,
                x,
                bottom,
                fill="#1e293b"
            )

            if tick_index == 0:
                label = "Start"
                anchor = "w"
            elif tick_index == 4:
                label = self.format_duration(duration)
                anchor = "e"
            else:
                label = self.format_duration(
                    duration * ratio
                )
                anchor = "center"

            self.visual_canvas.create_text(
                x,
                bottom + 24,
                text=label,
                fill="#9ca3af",
                font=("Segoe UI", 8),
                anchor=anchor
            )

        coordinates = []
        point_count = len(points)

        for index, point in enumerate(points):
            if point_count == 1:
                x = left
            else:
                x = left + (
                    index / (point_count - 1)
                ) * plot_width

            value = point.get(metric, 0)
            y = bottom - (
                value / maximum
            ) * plot_height

            coordinates.extend([x, y])

            midpoint = (
                point.get("start_offset_seconds", 0)
                + point.get("end_offset_seconds", 0)
            ) / 2

            self.visual_hover_items.append({
                "kind": "point",
                "x": x,
                "y": y,
                "plot_top": top,
                "plot_bottom": bottom,
                "text": (
                    f"{self.format_duration(midpoint)}\n"
                    f"{value:,} {value_label}\n"
                    f"{point.get('bytes', 0):,} bytes\n"
                    f"{point.get('dns_queries', 0):,} DNS queries\n"
                    f"{point.get('tcp_syn_attempts', 0):,} TCP SYN attempts"
                )
            })

        if len(coordinates) >= 4:
            self.visual_canvas.create_line(
                *coordinates,
                fill="#60a5fa",
                width=2
            )

        for item in self.visual_hover_items:
            if item.get("kind") == "point":
                self.visual_canvas.create_oval(
                    item["x"] - 3,
                    item["y"] - 3,
                    item["x"] + 3,
                    item["y"] + 3,
                    fill="#93c5fd",
                    outline=""
                )

        if include_findings:
            markers = visual.get(
                "finding_markers",
                []
            )

            marker_positions = []

            for marker in markers:
                if duration and duration > 0:
                    ratio = min(
                        max(
                            marker.get(
                                "offset_seconds",
                                0
                            ) / duration,
                            0
                        ),
                        1
                    )
                else:
                    ratio = 0

                marker_positions.append(
                    (
                        left + ratio * plot_width,
                        marker
                    )
                )

            marker_positions.sort(
                key=lambda item: item[0]
            )

            previous_x = None
            marker_lane = 0

            for x, marker in marker_positions:
                if (
                    previous_x is not None
                    and abs(x - previous_x) < 105
                ):
                    marker_lane = (
                        marker_lane + 1
                    ) % 3
                else:
                    marker_lane = 0

                previous_x = x

                color = self.get_assessment_color(
                    marker.get(
                        "assessment",
                        "LIKELY NORMAL"
                    )
                )

                self.visual_canvas.create_line(
                    x,
                    top,
                    x,
                    bottom,
                    fill=color,
                    dash=(4, 4)
                )

                label_y = (
                    top + 7 + marker_lane * 17
                )

                if x > right - 110:
                    label_x = x - 4
                    label_anchor = "ne"
                else:
                    label_x = x + 4
                    label_anchor = "nw"

                self.visual_canvas.create_text(
                    label_x,
                    label_y,
                    text=marker.get(
                        "finding_id",
                        "FINDING"
                    ),
                    fill=color,
                    font=("Segoe UI", 8, "bold"),
                    anchor=label_anchor
                )

                finding_id = marker.get(
                    "finding_id",
                    "FINDING"
                )

                approx_width = max(
                    55,
                    len(str(finding_id)) * 7
                )

                if label_anchor == "nw":
                    label_left = label_x
                    label_right = label_x + approx_width
                else:
                    label_left = label_x - approx_width
                    label_right = label_x

                self.visual_hover_items.append({
                    "kind": "marker",
                    "x": x,
                    "y1": top,
                    "y2": bottom,
                    "label_left": label_left,
                    "label_right": label_right,
                    "label_top": label_y - 4,
                    "label_bottom": label_y + 13,
                    "finding_id": finding_id,
                    "text": (
                        f"{finding_id}\n"
                        f"{marker.get('type')}\n"
                        f"{marker.get('risk_score', 0)}/100 "
                        f"{marker.get('assessment')}\n"
                        f"First seen at "
                        f"{self.format_duration(marker.get('offset_seconds', 0))}"
                        "\nClick to open Finding Investigation"
                    )
                })

        # A packet selected from Packet Evidence or Threat Hunt can be
        # pinned to its exact capture offset on the traffic timeline.
        selected_packet = getattr(
            self,
            "timeline_packet_marker",
            None
        )

        if (
            metric == "packets"
            and selected_packet
        ):
            packet_offset = selected_packet.get(
                "offset_seconds",
                0
            )

            if duration and duration > 0:
                packet_ratio = min(
                    max(
                        packet_offset / duration,
                        0
                    ),
                    1
                )
            else:
                packet_ratio = 0

            packet_x = left + packet_ratio * plot_width

            self.visual_canvas.create_line(
                packet_x,
                top,
                packet_x,
                bottom,
                fill="#22d3ee",
                width=3
            )

            self.visual_canvas.create_polygon(
                packet_x - 7,
                top,
                packet_x + 7,
                top,
                packet_x,
                top + 10,
                fill="#22d3ee",
                outline=""
            )

            packet_number = selected_packet.get(
                "packet_number",
                "?"
            )

            if packet_x > right - 170:
                packet_label_x = packet_x - 7
                packet_anchor = "ne"
            else:
                packet_label_x = packet_x + 7
                packet_anchor = "nw"

            self.visual_canvas.create_text(
                packet_label_x,
                bottom - 8,
                text=(
                    f"PACKET {packet_number}\n"
                    f"{self.format_duration(packet_offset)}"
                ),
                fill="#67e8f9",
                font=("Segoe UI", 8, "bold"),
                anchor=packet_anchor
            )

            self.visual_hover_items.append({
                "kind": "packet_marker",
                "x": packet_x,
                "y1": top,
                "y2": bottom,
                "text": (
                    f"Packet {packet_number}\n"
                    f"Capture offset: {self.format_duration(packet_offset)}\n"
                    f"{selected_packet.get('source', 'Unknown')} → "
                    f"{selected_packet.get('destination', 'Unknown')}\n"
                    f"Protocol: {selected_packet.get('protocol', 'Unknown')}"
                )
            })

    def draw_bar_chart(
        self,
        items,
        title,
        value_label,
        width,
        height,
        click_action=None
    ):
        if not items:
            self.draw_visual_empty_state(
                "No data is available for this chart.",
                width,
                height
            )
            return

        self.draw_chart_title(title)

        left = min(
            220,
            max(175, int(width * 0.20))
        )
        right = width - 34
        top = 52
        bottom = height - 24
        plot_width = max(right - left, 1)
        plot_height = max(bottom - top, 1)

        maximum = max(
            value
            for _, value in items
        ) or 1

        row_height = (
            plot_height / max(len(items), 1)
        )

        for index, (label, value) in enumerate(items):
            y1 = top + index * row_height + 4
            y2 = top + (
                index + 1
            ) * row_height - 4

            bar_width = (
                value / maximum
            ) * plot_width
            x2 = left + bar_width

            display_label = str(label)
            if len(display_label) > 28:
                display_label = (
                    display_label[:25] + "..."
                )

            self.visual_canvas.create_text(
                left - 10,
                (y1 + y2) / 2,
                text=display_label,
                fill="#d1d5db",
                font=("Segoe UI", 8),
                anchor="e"
            )
            self.visual_canvas.create_rectangle(
                left,
                y1,
                x2,
                y2,
                fill="#60a5fa",
                outline=""
            )
            self.visual_canvas.create_text(
                min(x2 + 8, right),
                (y1 + y2) / 2,
                text=f"{value:,}",
                fill="#e5e7eb",
                font=("Segoe UI", 8),
                anchor=(
                    "w"
                    if x2 + 55 < right
                    else "e"
                )
            )

            self.visual_hover_items.append({
                "kind": "bar",
                "x1": left,
                "x2": x2,
                "y1": y1,
                "y2": y2,
                "click_action": click_action,
                "click_value": label,
                "text": (
                    f"{label}\n"
                    f"{value:,} {value_label}"
                    + (
                        "\nClick to open Host Investigation"
                        if click_action == "host"
                        else ""
                    )
                )
            })

    def draw_network_relationship_map(
        self,
        width,
        height
    ):
        import math

        network_map = self.visual_report.get(
            "network_map",
            {}
        )

        nodes = network_map.get(
            "nodes",
            []
        )

        edges = network_map.get(
            "edges",
            []
        )

        if not nodes:
            self.draw_visual_empty_state(
                "No host relationship data is available.",
                width,
                height
            )
            return

        self.draw_chart_title(
            "Network Relationship Map"
        )

        left_pad = 95
        right_pad = 95
        top_pad = 72
        bottom_pad = 72

        center_x = width / 2
        center_y = (
            top_pad
            + (
                height
                - top_pad
                - bottom_pad
            ) / 2
        )

        available_width = max(
            width - left_pad - right_pad,
            260
        )
        available_height = max(
            height - top_pad - bottom_pad,
            200
        )

        outer_radius = max(
            105,
            min(
                available_width * 0.37,
                available_height * 0.44
            )
        )

        suspicious_nodes = [
            node
            for node in nodes
            if node.get("risk_score", 0) > 0
        ]
        normal_nodes = [
            node
            for node in nodes
            if node.get("risk_score", 0) <= 0
        ]

        suspicious_nodes.sort(
            key=lambda node: (
                node.get("risk_score", 0),
                node.get("packets", 0)
            ),
            reverse=True
        )
        normal_nodes.sort(
            key=lambda node: node.get("packets", 0),
            reverse=True
        )

        node_positions = {}

        if suspicious_nodes:
            if len(suspicious_nodes) == 1:
                node_positions[suspicious_nodes[0]["ip"]] = (
                    center_x,
                    center_y
                )
            else:
                inner_radius = min(
                    90,
                    outer_radius * 0.30
                )
                for index, node in enumerate(
                    suspicious_nodes
                ):
                    angle = (
                        2
                        * math.pi
                        * index
                        / len(suspicious_nodes)
                    ) - math.pi / 2

                    node_positions[node["ip"]] = (
                        center_x
                        + math.cos(angle)
                        * inner_radius,
                        center_y
                        + math.sin(angle)
                        * inner_radius
                    )

        first_ring = normal_nodes[:12]
        second_ring = normal_nodes[12:]

        for index, node in enumerate(first_ring):
            angle = (
                2
                * math.pi
                * index
                / max(len(first_ring), 1)
            ) - math.pi / 2

            node_positions[node["ip"]] = (
                center_x
                + math.cos(angle)
                * outer_radius,
                center_y
                + math.sin(angle)
                * outer_radius
            )

        if second_ring:
            second_radius = max(
                78,
                outer_radius * 0.68
            )

            for index, node in enumerate(
                second_ring
            ):
                angle = (
                    2
                    * math.pi
                    * index
                    / len(second_ring)
                ) - math.pi / 2 + 0.18

                node_positions[node["ip"]] = (
                    center_x
                    + math.cos(angle)
                    * second_radius,
                    center_y
                    + math.sin(angle)
                    * second_radius
                )

        max_edge_packets = max(
            (
                edge.get("packets", 0)
                for edge in edges
            ),
            default=1
        )

        for edge in edges:
            source_position = node_positions.get(
                edge.get("source")
            )
            target_position = node_positions.get(
                edge.get("target")
            )

            if (
                source_position is None
                or target_position is None
            ):
                continue

            x1, y1 = source_position
            x2, y2 = target_position

            relative = (
                edge.get("packets", 0)
                / max_edge_packets
            )

            line_width = max(
                1,
                min(
                    5,
                    1 + relative * 4
                )
            )

            self.visual_canvas.create_line(
                x1,
                y1,
                x2,
                y2,
                fill="#334155",
                width=line_width
            )

            self.visual_hover_items.append({
                "kind": "network_edge",
                "x1": x1,
                "y1": y1,
                "x2": x2,
                "y2": y2,
                "text": (
                    f"{edge.get('source')} ↔ "
                    f"{edge.get('target')}\n"
                    f"{edge.get('packets', 0):,} packets\n"
                    f"{edge.get('bytes', 0):,} bytes"
                )
            })

        max_node_packets = max(
            (
                node.get("packets", 0)
                for node in nodes
            ),
            default=1
        )

        labeled_normal_ips = {
            node["ip"]
            for node in normal_nodes[:5]
        }

        for node in nodes:
            position = node_positions.get(
                node["ip"]
            )

            if position is None:
                continue

            x, y = position
            relative = (
                node.get("packets", 0)
                / max_node_packets
            )
            risk_score = node.get(
                "risk_score",
                0
            )

            if risk_score > 0:
                node_size = (
                    16
                    + relative * 9
                )
            else:
                node_size = (
                    8
                    + relative * 8
                )

            assessment = node.get(
                "assessment",
                "LIKELY NORMAL"
            )

            if risk_score > 0:
                fill = self.get_assessment_color(
                    assessment
                )
                outline = "#ffffff"
                outline_width = 3
            else:
                fill = "#60a5fa"
                outline = "#93c5fd"
                outline_width = 2

            self.visual_canvas.create_oval(
                x - node_size,
                y - node_size,
                x + node_size,
                y + node_size,
                fill=fill,
                outline=outline,
                width=outline_width
            )

            should_label = (
                risk_score > 0
                or node["ip"]
                in labeled_normal_ips
            )

            if should_label:
                ip_text = str(
                    node["ip"]
                )

                if len(ip_text) > 27:
                    display_ip = (
                        ip_text[:24]
                        + "..."
                    )
                else:
                    display_ip = ip_text

                self.visual_canvas.create_text(
                    x,
                    y + node_size + 7,
                    text=display_ip,
                    fill=(
                        "#f9fafb"
                        if risk_score > 0
                        else "#cbd5e1"
                    ),
                    font=(
                        ("Segoe UI", 8, "bold")
                        if risk_score > 0
                        else ("Segoe UI", 8)
                    ),
                    anchor="n"
                )

            categories = node.get(
                "threat_categories",
                []
            )
            category_text = (
                ", ".join(categories)
                if categories
                else "None detected"
            )

            self.visual_hover_items.append({
                "kind": "network_node",
                "x": x,
                "y": y,
                "radius": node_size + 10,
                "ip": node["ip"],
                "text": (
                    f"{node['ip']}\n"
                    f"{node.get('packets', 0):,} packets\n"
                    f"{risk_score}/100 {assessment}\n"
                    f"Threat categories: {category_text}\n"
                    "Click to open Host Investigation"
                )
            })

        legend_x = width - 205
        legend_y = 22

        self.visual_canvas.create_oval(
            legend_x,
            legend_y,
            legend_x + 10,
            legend_y + 10,
            fill="#60a5fa",
            outline="#93c5fd"
        )
        self.visual_canvas.create_text(
            legend_x + 16,
            legend_y + 5,
            text="Normal / unflagged host",
            fill="#cbd5e1",
            font=("Segoe UI", 8),
            anchor="w"
        )

        self.visual_canvas.create_oval(
            legend_x,
            legend_y + 18,
            legend_x + 10,
            legend_y + 28,
            fill="#fbbf24",
            outline="#ffffff"
        )
        self.visual_canvas.create_text(
            legend_x + 16,
            legend_y + 23,
            text="Flagged host",
            fill="#cbd5e1",
            font=("Segoe UI", 8),
            anchor="w"
        )

        footer = (
            f"{network_map.get('node_count', len(nodes))} hosts shown  •  "
            f"{network_map.get('edge_count', len(edges))} relationships"
        )

        if network_map.get(
            "limited_to_top_hosts"
        ):
            footer += (
                "  •  limited to flagged and most active hosts"
            )

        self.visual_canvas.create_text(
            18,
            height - 12,
            text=footer,
            fill="#9ca3af",
            font=("Segoe UI", 8),
            anchor="sw"
        )

    def point_to_segment_distance(
        self,
        px,
        py,
        x1,
        y1,
        x2,
        y2
    ):
        dx = x2 - x1
        dy = y2 - y1

        if dx == 0 and dy == 0:
            return (
                (px - x1) ** 2
                + (py - y1) ** 2
            ) ** 0.5

        t = (
            (
                (px - x1) * dx
                + (py - y1) * dy
            )
            / (
                dx * dx
                + dy * dy
            )
        )

        t = max(
            0,
            min(
                1,
                t
            )
        )

        closest_x = x1 + t * dx
        closest_y = y1 + t * dy

        return (
            (
                px - closest_x
            ) ** 2
            + (
                py - closest_y
            ) ** 2
        ) ** 0.5

    def on_visual_hover(self, event):
        if not self.visual_hover_items:
            self.visual_canvas.config(cursor="")
            self.clear_visual_tooltip()
            return

        # Selected packet timeline marker.
        for item in self.visual_hover_items:
            if item.get("kind") != "packet_marker":
                continue

            if (
                abs(event.x - item.get("x", 0)) <= 7
                and item.get("y1", 0)
                <= event.y
                <= item.get("y2", 0)
            ):
                self.visual_canvas.config(
                    cursor=""
                )
                self.show_visual_tooltip(
                    event.x,
                    event.y,
                    item["text"]
                )
                return

        # Network map nodes are clickable.
        for item in self.visual_hover_items:
            if item.get("kind") != "network_node":
                continue

            distance = (
                (
                    event.x
                    - item["x"]
                ) ** 2
                + (
                    event.y
                    - item["y"]
                ) ** 2
            ) ** 0.5

            if distance <= item["radius"]:
                self.visual_canvas.config(
                    cursor="hand2"
                )
                self.show_visual_tooltip(
                    event.x,
                    event.y,
                    item["text"]
                )
                return

        # Network map edges show relationship details on hover.
        for item in self.visual_hover_items:
            if item.get("kind") != "network_edge":
                continue

            distance = self.point_to_segment_distance(
                event.x,
                event.y,
                item["x1"],
                item["y1"],
                item["x2"],
                item["y2"]
            )

            if distance <= 5:
                self.visual_canvas.config(
                    cursor=""
                )
                self.show_visual_tooltip(
                    event.x,
                    event.y,
                    item["text"]
                )
                return

        # Clickable bars, currently Most Active Hosts.
        for item in self.visual_hover_items:
            if item.get("kind") != "bar":
                continue

            if (
                item["x1"] <= event.x <= item["x2"]
                and item["y1"] <= event.y <= item["y2"]
            ):
                self.visual_canvas.config(
                    cursor=(
                        "hand2"
                        if item.get("click_action")
                        else ""
                    )
                )
                self.show_visual_tooltip(
                    event.x,
                    event.y,
                    item["text"]
                )
                return

        # Finding labels get their own hit area so stacked labels remain
        # individually selectable even when markers share the same time.
        for item in self.visual_hover_items:
            if item.get("kind") != "marker":
                continue

            if (
                item.get("label_left", 0)
                <= event.x
                <= item.get("label_right", 0)
                and item.get("label_top", 0)
                <= event.y
                <= item.get("label_bottom", 0)
            ):
                self.visual_canvas.config(
                    cursor="hand2"
                )
                self.show_visual_tooltip(
                    event.x,
                    event.y,
                    item["text"]
                )
                return

        # Timeline finding marker lines.
        marker_match = None
        marker_distance = None

        for item in self.visual_hover_items:
            if item.get("kind") != "marker":
                continue

            distance = abs(
                event.x - item["x"]
            )

            if (
                distance <= 14
                and item["y1"] <= event.y <= item["y2"]
            ):
                if (
                    marker_distance is None
                    or distance < marker_distance
                ):
                    marker_match = item
                    marker_distance = distance

        if marker_match is not None:
            self.visual_canvas.config(
                cursor="hand2"
            )
            self.show_visual_tooltip(
                event.x,
                event.y,
                marker_match["text"]
            )
            return

        # Timeline buckets: nearest X position anywhere in the plot.
        point_match = None
        point_distance = None

        for item in self.visual_hover_items:
            if item.get("kind") != "point":
                continue

            if not (
                item["plot_top"]
                <= event.y
                <= item["plot_bottom"]
            ):
                continue

            distance = abs(
                event.x - item["x"]
            )

            if (
                point_distance is None
                or distance < point_distance
            ):
                point_match = item
                point_distance = distance

        if point_match is not None:
            self.visual_canvas.config(cursor="")
            self.show_visual_tooltip(
                event.x,
                event.y,
                point_match["text"]
            )
            return

        self.visual_canvas.config(cursor="")
        self.clear_visual_tooltip()

    def on_visual_click(self, event):
        # Network relationship map nodes link to Host Investigation.
        for item in self.visual_hover_items:
            if item.get("kind") != "network_node":
                continue

            distance = (
                (
                    event.x
                    - item["x"]
                ) ** 2
                + (
                    event.y
                    - item["y"]
                ) ** 2
            ) ** 0.5

            if distance <= item["radius"]:
                self.open_host_by_ip(
                    item.get("ip")
                )
                return

        # Host bars link directly into Host Investigation.
        for item in self.visual_hover_items:
            if item.get("kind") != "bar":
                continue

            if (
                item["x1"] <= event.x <= item["x2"]
                and item["y1"] <= event.y <= item["y2"]
            ):
                if item.get("click_action") == "host":
                    self.open_host_by_ip(
                        item.get("click_value")
                    )
                return

        # Prefer the individually staggered finding label hitboxes.
        for item in self.visual_hover_items:
            if item.get("kind") != "marker":
                continue

            if (
                item.get("label_left", 0)
                <= event.x
                <= item.get("label_right", 0)
                and item.get("label_top", 0)
                <= event.y
                <= item.get("label_bottom", 0)
            ):
                self.open_finding_by_id(
                    item.get("finding_id")
                )
                return

        # Clicking the marker line also opens the nearest finding.
        marker_match = None
        marker_distance = None

        for item in self.visual_hover_items:
            if item.get("kind") != "marker":
                continue

            distance = abs(
                event.x - item["x"]
            )

            if (
                distance <= 14
                and item["y1"] <= event.y <= item["y2"]
            ):
                if (
                    marker_distance is None
                    or distance < marker_distance
                ):
                    marker_match = item
                    marker_distance = distance

        if marker_match is not None:
            self.open_finding_by_id(
                marker_match.get("finding_id")
            )

    def show_visual_tooltip(self, x, y, text):
        self.clear_visual_tooltip()

        text_id = self.visual_canvas.create_text(
            x + 22,
            y + 21,
            text=text,
            fill="#f9fafb",
            font=("Segoe UI", 8),
            anchor="nw",
            tags="visual_tooltip"
        )

        bbox = self.visual_canvas.bbox(text_id)

        if bbox:
            padding = 6
            rect_id = self.visual_canvas.create_rectangle(
                bbox[0] - padding,
                bbox[1] - padding,
                bbox[2] + padding,
                bbox[3] + padding,
                fill="#1f2937",
                outline="#4b5563",
                tags="visual_tooltip"
            )
            self.visual_canvas.tag_lower(
                rect_id,
                text_id
            )

    def clear_visual_tooltip(self, event=None):
        if hasattr(self, "visual_canvas"):
            self.visual_canvas.delete(
                "visual_tooltip"
            )

    def create_host_investigation_tab(self):
        frame = ttk.Frame(
            self.notebook,
            style="Card.TFrame"
        )
        self.notebook.add(
            frame,
            text="Host Investigation"
        )

        container = ttk.Frame(
            frame,
            style="Card.TFrame",
            padding=10
        )
        container.pack(fill="both", expand=True)

        # ----------------------------------------------------------
        # LEFT PANEL: HOST LIST + FILTERS
        # ----------------------------------------------------------
        left_panel = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        left_panel.pack(
            side="left",
            fill="both",
            padx=(0, 10)
        )

        left_header = ttk.Frame(
            left_panel,
            style="Card.TFrame"
        )
        left_header.pack(fill="x", pady=(0, 8))

        ttk.Label(
            left_header,
            text="Observed Hosts",
            style="Body.TLabel"
        ).pack(side="left")

        self.host_count_label = ttk.Label(
            left_header,
            text="0 hosts",
            style="CardMuted.TLabel"
        )
        self.host_count_label.pack(side="right")

        search_frame = ttk.Frame(
            left_panel,
            style="Card.TFrame"
        )
        search_frame.pack(fill="x", pady=(0, 7))

        self.host_search_var = tk.StringVar()

        self.host_search_entry = tk.Entry(
            search_frame,
            textvariable=self.host_search_var,
            font=("Segoe UI", 9),
            bg="#111827",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            relief="flat",
            highlightthickness=1,
            highlightbackground="#374151",
            highlightcolor="#60a5fa"
        )
        self.host_search_entry.pack(
            side="left",
            fill="x",
            expand=True,
            ipady=5
        )

        self.host_search_var.trace_add(
            "write",
            self.refresh_host_list
        )

        self.flagged_only_var = tk.BooleanVar(value=False)

        self.flagged_only_checkbox = ttk.Checkbutton(
            search_frame,
            text="Flagged only",
            variable=self.flagged_only_var,
            command=self.refresh_host_list,
            style="Option.TCheckbutton"
        )
        self.flagged_only_checkbox.pack(
            side="left",
            padx=(8, 0)
        )

        tree_frame = ttk.Frame(
            left_panel,
            style="Card.TFrame"
        )
        tree_frame.pack(fill="both", expand=True)

        host_scrollbar = ttk.Scrollbar(
            tree_frame,
            orient="vertical"
        )
        host_scrollbar.pack(
            side="right",
            fill="y"
        )

        self.host_tree = ttk.Treeview(
            tree_frame,
            columns=("risk", "ip", "status"),
            show="headings",
            height=12,
            yscrollcommand=host_scrollbar.set
        )
        self.host_tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        host_scrollbar.config(
            command=self.host_tree.yview
        )

        self.host_tree.heading(
            "risk",
            text="Risk"
        )
        self.host_tree.heading(
            "ip",
            text="IP Address"
        )
        self.host_tree.heading(
            "status",
            text="Assessment"
        )

        self.host_tree.column(
            "risk",
            width=62,
            minwidth=55,
            anchor="center",
            stretch=False
        )
        self.host_tree.column(
            "ip",
            width=225,
            minwidth=170,
            anchor="w",
            stretch=True
        )
        self.host_tree.column(
            "status",
            width=125,
            minwidth=115,
            anchor="center",
            stretch=False
        )

        self.host_tree.bind(
            "<<TreeviewSelect>>",
            self.on_host_selected
        )

        # ----------------------------------------------------------
        # RIGHT PANEL: SELECTED HOST DETAILS
        # ----------------------------------------------------------
        right_panel = ttk.Frame(
            container,
            style="Card.TFrame"
        )
        right_panel.pack(
            side="left",
            fill="both",
            expand=True
        )

        host_summary_bar = ttk.Frame(
            right_panel,
            style="Card.TFrame"
        )
        host_summary_bar.pack(
            fill="x",
            pady=(0, 8)
        )

        self.selected_host_label = ttk.Label(
            host_summary_bar,
            text="Select a host",
            style="Body.TLabel"
        )
        self.selected_host_label.pack(
            side="left"
        )

        self.selected_host_risk_label = ttk.Label(
            host_summary_bar,
            text="-- / 100",
            style="CardMuted.TLabel"
        )
        self.selected_host_risk_label.pack(
            side="right"
        )

        host_correlation_bar = ttk.Frame(
            right_panel,
            style="Card.TFrame"
        )
        host_correlation_bar.pack(
            fill="x",
            pady=(0, 8)
        )

        self.host_related_finding_var = tk.StringVar()

        self.host_related_finding_combo = ttk.Combobox(
            host_correlation_bar,
            textvariable=self.host_related_finding_var,
            state="readonly",
            width=46
        )
        self.host_related_finding_combo.pack(
            side="left",
            fill="x",
            expand=True
        )

        self.open_host_finding_button = ttk.Button(
            host_correlation_bar,
            text="Open Related Finding",
            command=self.open_related_finding_from_host,
            state="disabled",
            style="Secondary.TButton"
        )
        self.open_host_finding_button.pack(
            side="left",
            padx=(8, 0)
        )

        self.add_host_queue_button = ttk.Button(
            host_correlation_bar,
            text="Add Host to Queue",
            command=self.add_current_host_to_queue,
            state="disabled",
            style="Secondary.TButton"
        )
        self.add_host_queue_button.pack(
            side="left",
            padx=(8, 0)
        )

        detail_frame = ttk.Frame(
            right_panel,
            style="Card.TFrame"
        )
        detail_frame.pack(
            fill="both",
            expand=True
        )

        detail_scrollbar = ttk.Scrollbar(
            detail_frame,
            orient="vertical"
        )
        detail_scrollbar.pack(
            side="right",
            fill="y"
        )

        self.host_detail_text = tk.Text(
            detail_frame,
            wrap="word",
            font=("Consolas", 10),
            bg="#0f172a",
            fg="#e5e7eb",
            insertbackground="#ffffff",
            selectbackground="#374151",
            relief="flat",
            padx=14,
            pady=12,
            yscrollcommand=detail_scrollbar.set,
            state="disabled"
        )
        self.host_detail_text.pack(
            side="left",
            fill="both",
            expand=True
        )

        detail_scrollbar.config(
            command=self.host_detail_text.yview
        )

        self.host_records = []
        self.filtered_host_records = []
        self.current_host = None

        return frame

    def display_hosts(self, report):
        self.host_records = list(
            report.get("hosts", [])
        )

        self.host_search_var.set("")
        self.flagged_only_var.set(False)

        self.refresh_host_list()

    def refresh_host_list(self, *args):
        if not hasattr(self, "host_tree"):
            return

        search_text = self.host_search_var.get().strip().lower()
        flagged_only = self.flagged_only_var.get()

        filtered = []

        for host in self.host_records:
            ip = str(host.get("ip", "Unknown"))
            assessment = str(
                host.get("assessment", "LIKELY NORMAL")
            )
            categories = " ".join(
                host.get("threat_categories", [])
            )

            searchable = (
                f"{ip} {assessment} {categories}"
            ).lower()

            if search_text and search_text not in searchable:
                continue

            if flagged_only and host.get("risk_score", 0) <= 0:
                continue

            filtered.append(host)

        self.filtered_host_records = filtered

        for item in self.host_tree.get_children():
            self.host_tree.delete(item)

        for index, host in enumerate(filtered):
            ip = host.get("ip", "Unknown")
            score = host.get("risk_score", 0)
            assessment = host.get(
                "assessment",
                "LIKELY NORMAL"
            )

            tag = self.get_host_tree_tag(
                assessment,
                score
            )

            self.host_tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    f"{score}/100",
                    ip,
                    assessment
                ),
                tags=(tag,)
            )

        self.host_tree.tag_configure(
            "high",
            foreground="#f87171"
        )
        self.host_tree.tag_configure(
            "suspicious",
            foreground="#fbbf24"
        )
        self.host_tree.tag_configure(
            "review",
            foreground="#facc15"
        )
        self.host_tree.tag_configure(
            "normal",
            foreground="#d1d5db"
        )

        total = len(self.host_records)
        shown = len(filtered)

        if total == shown:
            count_text = f"{total:,} hosts"
        else:
            count_text = f"{shown:,} of {total:,}"

        self.host_count_label.config(
            text=count_text
        )

        if filtered:
            first_item = self.host_tree.get_children()[0]
            self.host_tree.selection_set(first_item)
            self.host_tree.focus(first_item)
            self.host_tree.see(first_item)
            self.show_host_details(filtered[0])
        else:
            self.selected_host_label.config(
                text="No matching hosts"
            )
            self.selected_host_risk_label.config(
                text="-- / 100",
                foreground="#9ca3af"
            )
            self.set_text(
                self.host_detail_text,
                "No hosts match the current filter."
            )

    def get_host_tree_tag(
        self,
        assessment,
        score
    ):
        assessment = str(assessment).upper()

        if assessment == "HIGH RISK" or score >= 75:
            return "high"

        if assessment == "SUSPICIOUS" or score >= 50:
            return "suspicious"

        if (
            assessment == "REVIEW RECOMMENDED"
            or score >= 25
        ):
            return "review"

        return "normal"

    def on_host_selected(self, event=None):
        selection = self.host_tree.selection()

        if not selection:
            return

        try:
            index = int(selection[0])
        except Exception:
            return

        if index >= len(self.filtered_host_records):
            return

        self.show_host_details(
            self.filtered_host_records[index]
        )

    def open_related_finding_from_host(self):
        selection = self.host_related_finding_var.get()

        if not selection:
            return

        finding_id = getattr(
            self,
            "host_related_finding_lookup",
            {}
        ).get(
            selection
        )

        if not finding_id:
            return

        self.open_finding_by_id(
            finding_id
        )

    def show_host_details(self, host):
        self.current_host = host

        ip = host.get("ip", "Unknown")
        score = host.get("risk_score", 0)
        assessment = host.get(
            "assessment",
            "LIKELY NORMAL"
        )

        risk_color = self.get_assessment_color(
            assessment
        )

        self.selected_host_label.config(
            text=f"Selected Host: {ip}"
        )
        self.selected_host_risk_label.config(
            text=f"{score} / 100  •  {assessment}",
            foreground=risk_color
        )

        if hasattr(self, "add_host_queue_button"):
            self.add_host_queue_button.config(
                state="normal"
            )

        related_finding_choices = []
        self.host_related_finding_lookup = {}

        for finding in getattr(
            self,
            "finding_records",
            []
        ):
            finding_id = finding.get(
                "finding_id"
            )

            if not finding_id:
                continue

            related = any(
                str(
                    related_host.get(
                        "ip",
                        ""
                    )
                )
                == str(ip)
                for related_host in finding.get(
                    "related_hosts",
                    []
                )
            )

            if not related:
                continue

            label = (
                f"{finding_id}  •  "
                f"{finding.get('type', 'FINDING')}"
            )

            related_finding_choices.append(
                label
            )
            self.host_related_finding_lookup[
                label
            ] = finding_id

        self.host_related_finding_combo[
            "values"
        ] = related_finding_choices

        if related_finding_choices:
            self.host_related_finding_var.set(
                related_finding_choices[0]
            )
            self.open_host_finding_button.config(
                state="normal"
            )
        else:
            self.host_related_finding_var.set(
                "No directly related structured findings"
            )
            self.open_host_finding_button.config(
                state="disabled"
            )

        categories = host.get(
            "threat_categories",
            []
        )

        top_destinations = host.get(
            "top_destinations",
            []
        )

        top_ports = host.get(
            "top_destination_ports",
            []
        )

        dns_domains = host.get(
            "top_dns_queries",
            []
        )

        protocols = host.get(
            "protocols",
            {}
        )

        total_packets = (
            host.get("packets_sent", 0)
            + host.get("packets_received", 0)
        )

        total_bytes = (
            host.get("bytes_sent", 0)
            + host.get("bytes_received", 0)
        )

        lines = [
            "HOST INVESTIGATION",
            "=" * 72,
            "",
            "IDENTITY & RISK",
            "-" * 72,
            f"IP Address:              {ip}",
            f"Address Type:            "
            f"{'Private' if host.get('private') else 'External / Other'}",
            f"Host Risk Score:         {score}/100",
            f"Assessment:              {assessment}",
            "",
            "TRAFFIC ACTIVITY",
            "-" * 72,
            f"Total Packets:           {total_packets:,}",
            f"Packets Sent:            {host.get('packets_sent', 0):,}",
            f"Packets Received:        {host.get('packets_received', 0):,}",
            f"Total Bytes:             {total_bytes:,}",
            f"Bytes Sent:              {host.get('bytes_sent', 0):,}",
            f"Bytes Received:          {host.get('bytes_received', 0):,}",
            f"TCP SYN Attempts:        {host.get('tcp_syn_attempts', 0):,}",
            f"DNS Queries:             {host.get('dns_queries', 0):,}",
            f"Unique DNS Domains:      {host.get('unique_dns_domains', 0):,}",
            "",
            "DETECTION CORRELATION",
            "-" * 72,
            f"Port Scans Started:      {host.get('port_scans_started', 0):,}",
            f"Port Scans Received:     {host.get('port_scans_received', 0):,}",
            f"Outbound Findings:       {host.get('outbound_findings', 0):,}",
            f"Related Flow Findings:   {host.get('related_flow_findings', 0):,}",
            "",
            "THREAT CATEGORIES",
            "-" * 72
        ]

        if categories:
            for category in categories:
                lines.append(
                    f"  • {category}"
                )
        else:
            lines.append(
                "  None detected"
            )

        lines.extend([
            "",
            "TOP DESTINATIONS",
            "-" * 72
        ])

        if top_destinations:
            for item in top_destinations:
                destination = item.get(
                    "ip",
                    "Unknown"
                )
                count = item.get(
                    "packets",
                    0
                )

                lines.append(
                    f"  {destination:<40} {count:>8,} packets"
                )
        else:
            lines.append(
                "  No destination data available"
            )

        lines.extend([
            "",
            "TOP DESTINATION PORTS",
            "-" * 72
        ])

        if top_ports:
            for item in top_ports:
                port = item.get(
                    "port",
                    "Unknown"
                )
                count = item.get(
                    "packets",
                    0
                )

                lines.append(
                    f"  Port {str(port):<8} {count:>10,} packets"
                )
        else:
            lines.append(
                "  No destination-port data available"
            )

        lines.extend([
            "",
            "DNS ACTIVITY",
            "-" * 72
        ])

        if dns_domains:
            for item in dns_domains:
                domain = item.get(
                    "domain",
                    "Unknown"
                )
                count = item.get(
                    "queries",
                    0
                )

                lines.append(
                    f"  {domain}: {count:,} queries"
                )
        else:
            lines.append(
                "  No DNS domains recorded for this host"
            )

        lines.extend([
            "",
            "PROTOCOL BREAKDOWN",
            "-" * 72
        ])

        if protocols:
            for protocol, count in sorted(
                protocols.items(),
                key=lambda item: item[1],
                reverse=True
            ):
                lines.append(
                    f"  {protocol:<15} {count:>10,} packets"
                )
        else:
            lines.append(
                "  No protocol data available"
            )

        lines.extend([
            "",
            "ANALYST NOTE",
            "-" * 72,
            (
                "Host-level findings are behavioral indicators for "
                "defensive review. A host being contacted or scanned "
                "does not by itself mean that host is compromised."
            )
        ])

        self.set_text(
            self.host_detail_text,
            "\n".join(lines)
        )

    def utc_now_string(self):
        return (
            datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def calculate_file_sha256(self, file_path):
        path = Path(file_path)
        digest = hashlib.sha256()

        with open(path, "rb") as source_file:
            while True:
                chunk = source_file.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)

        return digest.hexdigest()

    def build_case_metadata(self, save_path):
        existing = (
            self.current_case_metadata
            if isinstance(self.current_case_metadata, dict)
            else {}
        )

        now = self.utc_now_string()

        capture_stem = (
            self.selected_file.stem
            if self.selected_file
            else "pcap-investigation"
        )

        metadata = {
            "case_id": existing.get(
                "case_id",
                str(uuid.uuid4())
            ),
            "case_name": existing.get(
                "case_name",
                capture_stem
            ),
            "created_at_utc": existing.get(
                "created_at_utc",
                existing.get("saved_at_utc", now)
            ),
            "last_saved_at_utc": now,
            "saved_by_application_version": APP_VERSION,
            "case_file_name": Path(save_path).name
        }

        return metadata

    def verify_case_capture(self, capture, source_path):
        result = {
            "status": "missing",
            "label": "source PCAP not found",
            "current_sha256": None
        }

        if not source_path:
            return result

        path = Path(source_path)

        try:
            if not path.exists():
                return result
        except OSError:
            return result

        stored_hash = str(
            capture.get("sha256") or ""
        ).strip().lower()

        if stored_hash:
            try:
                current_hash = self.calculate_file_sha256(path)
            except Exception as error:
                return {
                    "status": "error",
                    "label": f"verification error: {error}",
                    "current_sha256": None
                }

            if current_hash.lower() == stored_hash:
                return {
                    "status": "verified",
                    "label": "SHA-256 verified",
                    "current_sha256": current_hash
                }

            return {
                "status": "mismatch",
                "label": "SHA-256 mismatch",
                "current_sha256": current_hash
            }

        # Backward compatibility for the first v1.5 case format, which
        # did not yet save a cryptographic hash.
        try:
            stat = path.stat()
        except OSError:
            return {
                "status": "unverified",
                "label": "source available, integrity not verified",
                "current_sha256": None
            }

        stored_size = capture.get("size_bytes")
        stored_mtime = capture.get("modified_time_ns")

        size_matches = (
            stored_size is None
            or stored_size == stat.st_size
        )
        mtime_matches = (
            stored_mtime is None
            or stored_mtime == stat.st_mtime_ns
        )

        if size_matches and mtime_matches:
            return {
                "status": "legacy_match",
                "label": "legacy metadata match, no saved SHA-256",
                "current_sha256": None
            }

        return {
            "status": "legacy_changed",
            "label": "source metadata changed, no saved SHA-256",
            "current_sha256": None
        }

    def build_case_capture_metadata(self):
        capture_path = (
            str(self.selected_file)
            if self.selected_file
            else None
        )

        metadata = {
            "path": capture_path,
            "name": (
                self.selected_file.name
                if self.selected_file
                else None
            ),
            "exists_at_save": False,
            "size_bytes": None,
            "modified_time_ns": None,
            "hash_algorithm": "SHA-256",
            "sha256": None
        }

        if self.selected_file:
            try:
                if self.selected_file.exists():
                    stat = self.selected_file.stat()
                    metadata["exists_at_save"] = True
                    metadata["size_bytes"] = stat.st_size
                    metadata["modified_time_ns"] = stat.st_mtime_ns
                    metadata["sha256"] = self.calculate_file_sha256(
                        self.selected_file
                    )
            except (OSError, IOError):
                pass

        return metadata

    def build_case_queue_records(self):
        self.persist_current_queue_note(
            show_status=False
        )

        records = []

        for record in getattr(
            self,
            "investigation_queue_records",
            []
        ):
            records.append({
                "type": record.get("type"),
                "identifier": record.get("identifier"),
                "context": record.get("context", ""),
                "note": record.get("note", ""),
                "payload": record.get("payload", {})
            })

        return records

    def save_investigation_case(self):
        if self.analysis_running:
            return

        if not self.report_data:
            messagebox.showinfo(
                "No Analysis to Save",
                "Analyze a PCAP or load an existing case before saving a case."
            )
            return

        capture_name = (
            self.selected_file.stem
            if self.selected_file
            else "pcap"
        )

        if self.current_case_path:
            default_name = self.current_case_path.name
        else:
            default_name = (
                f"{capture_name}_investigation.pcapcase.json"
            )

        save_path = filedialog.asksaveasfilename(
            title="Save Investigation Case",
            defaultextension=".pcapcase.json",
            initialfile=default_name,
            filetypes=[
                (
                    "AI PCAP Case Files",
                    "*.pcapcase.json"
                ),
                ("JSON Files", "*.json"),
                ("All Files", "*.*")
            ]
        )

        if not save_path:
            return

        case_metadata = self.build_case_metadata(
            save_path
        )

        case_data = {
            "case_file_type": CASE_FILE_TYPE,
            "case_format_version": CASE_FORMAT_VERSION,
            "application_version": APP_VERSION,
            "saved_at_utc": case_metadata[
                "last_saved_at_utc"
            ],
            "case_metadata": case_metadata,
            "capture": self.build_case_capture_metadata(),
            "analysis_report": self.report_data,
            "investigation_queue": self.build_case_queue_records()
        }

        try:
            with open(
                save_path,
                "w",
                encoding="utf-8"
            ) as case_file:
                json.dump(
                    case_data,
                    case_file,
                    indent=2,
                    default=str
                )
        except Exception as error:
            messagebox.showerror(
                "Case Save Failed",
                "The investigation case could not be saved.\n\n"
                f"{error}"
            )
            return

        self.current_case_path = Path(save_path)
        self.current_case_metadata = case_metadata

        self.case_status_label.config(
            text=(
                f"Case: {case_metadata.get('case_name', 'Investigation')}  •  "
                f"ID {case_metadata.get('case_id', '')[:8]}  •  "
                "source SHA-256 saved"
            )
        )

        self.status_label.config(
            text=(
                "Investigation case saved | "
                f"{len(case_data['investigation_queue'])} queued item"
                + (
                    ""
                    if len(case_data["investigation_queue"]) == 1
                    else "s"
                )
            )
        )

        messagebox.showinfo(
            "Case Saved",
            "Investigation case saved successfully.\n\n"
            f"{save_path}"
        )

    def normalize_loaded_queue_records(self, records):
        normalized = []

        if not isinstance(records, list):
            return normalized

        for record in records:
            if not isinstance(record, dict):
                continue

            item_type = str(
                record.get("type", "")
            ).strip()
            identifier = str(
                record.get("identifier", "")
            ).strip()

            if not item_type or not identifier:
                continue

            payload = record.get(
                "payload",
                {}
            )

            if not isinstance(payload, dict):
                payload = {}

            normalized.append({
                "key": self.make_queue_key(
                    item_type,
                    identifier
                ),
                "type": item_type,
                "identifier": identifier,
                "context": str(
                    record.get("context", "")
                ),
                "note": str(
                    record.get(
                        "note",
                        record.get(
                            "analyst_note",
                            ""
                        )
                    )
                ),
                "payload": payload
            })

        return normalized

    def restore_case_report_paths(self, report):
        self.txt_report_path = None
        self.json_report_path = None
        self.csv_report_path = None

        self.open_txt_button.config(
            state="disabled"
        )
        self.open_json_button.config(
            state="disabled"
        )
        self.open_csv_button.config(
            state="disabled"
        )
        self.open_folder_button.config(
            state="disabled"
        )

        export_info = report.get(
            "report_export",
            {}
        )

        path_settings = [
            (
                "txt_path",
                "txt_report_path",
                self.open_txt_button
            ),
            (
                "json_path",
                "json_report_path",
                self.open_json_button
            ),
            (
                "csv_path",
                "csv_report_path",
                self.open_csv_button
            )
        ]

        any_report_available = False

        for report_key, attr_name, button in path_settings:
            raw_path = export_info.get(
                report_key
            )

            if not raw_path:
                continue

            path = Path(raw_path)

            if not path.exists():
                continue

            setattr(
                self,
                attr_name,
                str(path)
            )
            button.config(
                state="normal"
            )
            any_report_available = True

        if any_report_available:
            self.open_folder_button.config(
                state="normal"
            )

    def load_investigation_case(self):
        if self.analysis_running:
            return

        case_path = filedialog.askopenfilename(
            title="Load Investigation Case",
            filetypes=[
                (
                    "AI PCAP Case Files",
                    "*.pcapcase.json"
                ),
                ("JSON Files", "*.json"),
                ("All Files", "*.*")
            ]
        )

        if not case_path:
            return

        try:
            with open(
                case_path,
                "r",
                encoding="utf-8"
            ) as case_file:
                case_data = json.load(
                    case_file
                )
        except Exception as error:
            messagebox.showerror(
                "Case Load Failed",
                "The selected case file could not be read.\n\n"
                f"{error}"
            )
            return

        if not isinstance(case_data, dict):
            messagebox.showerror(
                "Invalid Case File",
                "The selected file is not a valid investigation case."
            )
            return

        if case_data.get("case_file_type") != CASE_FILE_TYPE:
            messagebox.showerror(
                "Invalid Case File",
                "The selected JSON file is not an AI PCAP Security Analyzer case."
            )
            return

        version = case_data.get(
            "case_format_version"
        )

        if version not in SUPPORTED_CASE_FORMAT_VERSIONS:
            messagebox.showerror(
                "Unsupported Case Version",
                (
                    f"This case uses format version {version}. "
                    "This build supports case format versions "
                    f"{sorted(SUPPORTED_CASE_FORMAT_VERSIONS)}."
                )
            )
            return

        report = case_data.get(
            "analysis_report"
        )

        if not isinstance(report, dict):
            messagebox.showerror(
                "Invalid Case File",
                "The case does not contain a valid saved analysis report."
            )
            return

        capture = case_data.get(
            "capture",
            {}
        )

        if not isinstance(capture, dict):
            capture = {}

        loaded_case_metadata = case_data.get(
            "case_metadata",
            {}
        )

        if not isinstance(loaded_case_metadata, dict):
            loaded_case_metadata = {}

        if not loaded_case_metadata:
            legacy_saved_at = case_data.get(
                "saved_at_utc",
                self.utc_now_string()
            )
            loaded_case_metadata = {
                "case_id": str(uuid.uuid4()),
                "case_name": Path(
                    capture.get("name") or "pcap-investigation"
                ).stem,
                "created_at_utc": legacy_saved_at,
                "last_saved_at_utc": legacy_saved_at,
                "saved_by_application_version": case_data.get(
                    "application_version",
                    "unknown"
                )
            }

        capture_path = capture.get(
            "path"
        )
        capture_name = capture.get(
            "name"
        ) or "Loaded PCAP Case"

        self.clear_results()

        if capture_path:
            self.selected_file = Path(
                capture_path
            )
        else:
            self.selected_file = Path(
                capture_name
            )

        source_available = False

        try:
            source_available = self.selected_file.exists()
        except OSError:
            source_available = False

        verification = self.verify_case_capture(
            capture,
            self.selected_file if source_available else None
        )

        file_display_name = (
            self.selected_file.name
            if source_available
            else f"{capture_name} (case only)"
        )

        if verification.get("status") in {
            "mismatch",
            "legacy_changed"
        }:
            file_display_name = (
                f"{capture_name} (source changed)"
            )

        self.file_label.config(
            text=file_display_name
        )

        self.analyze_button.config(
            state=(
                "normal"
                if source_available
                else "disabled"
            )
        )

        self.report_data = report
        self.current_case_path = Path(
            case_path
        )
        self.current_case_metadata = loaded_case_metadata

        self.case_status_label.config(
            text=(
                f"Case: {loaded_case_metadata.get('case_name', 'Investigation')}  •  "
                f"ID {loaded_case_metadata.get('case_id', '')[:8]}  •  "
                f"{verification.get('label', 'source not verified')}"
            )
        )

        self.display_results(
            report
        )

        self.investigation_queue_records = (
            self.normalize_loaded_queue_records(
                case_data.get(
                    "investigation_queue",
                    []
                )
            )
        )
        self.current_queue_index = None
        self.refresh_investigation_queue()

        self.restore_case_report_paths(
            report
        )

        self.progress_bar.config(
            value=100
        )
        self.save_case_button.config(
            state="normal"
        )

        queued_count = len(
            self.investigation_queue_records
        )

        source_status = verification.get(
            "label",
            (
                "source PCAP available"
                if source_available
                else "source PCAP unavailable, saved analysis restored"
            )
        )

        self.status_label.config(
            text=(
                f"Case loaded | {queued_count} queued item"
                f"{'' if queued_count == 1 else 's'} | "
                f"{source_status}"
            )
        )

        self.notebook.select(
            0
        )

        load_message = (
            "Investigation case loaded successfully.\n\n"
            f"Case: {loaded_case_metadata.get('case_name', 'Investigation')}\n"
            f"Capture: {capture_name}\n"
            f"Queued items: {queued_count}\n"
            f"Source integrity: {verification.get('label', 'not verified')}"
        )

        if verification.get("status") in {
            "mismatch",
            "legacy_changed"
        }:
            load_message += (
                "\n\nWarning: the PCAP currently at the saved path does not "
                "match the source information stored in this case. The saved "
                "analysis was restored, but treat the current PCAP as a "
                "different source until it is verified."
            )
            messagebox.showwarning(
                "Case Loaded - Source Changed",
                load_message
            )
        else:
            messagebox.showinfo(
                "Case Loaded",
                load_message
            )

    def select_pcap(self):
        if self.analysis_running:
            return

        file_path = filedialog.askopenfilename(
            title="Select a PCAP File",
            filetypes=[
                ("PCAP Files", "*.pcap *.pcapng *.cap"),
                ("All Files", "*.*")
            ]
        )

        if not file_path:
            return

        self.selected_file = Path(file_path)

        self.file_label.config(
            text=self.selected_file.name
        )

        self.analyze_button.config(
            state="normal"
        )

        self.status_label.config(
            text="PCAP selected and ready to analyze"
        )

        self.clear_results()

    def clear_results(self):
        self.report_data = None
        self.current_case_path = None
        self.current_case_metadata = None

        if hasattr(self, "case_status_label"):
            self.case_status_label.config(
                text="No investigation case loaded"
            )

        self.progress_bar.config(value=0)
        self.txt_report_path = None
        self.json_report_path = None
        self.csv_report_path = None

        self.open_txt_button.config(state="disabled")
        self.open_json_button.config(state="disabled")
        self.open_csv_button.config(state="disabled")
        self.open_folder_button.config(state="disabled")

        if hasattr(self, "save_case_button"):
            self.save_case_button.config(
                state="disabled"
            )

        self.assessment_card.config(
            text="Not Analyzed",
            foreground="#f9fafb"
        )

        self.score_card.config(
            text="-- / 100",
            foreground="#f9fafb"
        )

        self.packet_card.config(
            text="--"
        )

        self.categories_label.config(
            text="None detected"
        )

        if hasattr(self, "investigation_queue_records"):
            self.investigation_queue_records = []
            self.current_queue_index = None
            self.refresh_investigation_queue()

        if hasattr(self, "threat_hunt_query_var"):
            self.threat_hunt_query_var.set("")

        self.threat_hunt_result = None
        self.threat_hunt_host_records = []
        self.threat_hunt_finding_records = []

        for tree_name in [
            "threat_hunt_host_tree",
            "threat_hunt_finding_tree",
            "threat_hunt_packet_tree",
            "threat_hunt_relationship_tree"
        ]:
            tree = getattr(
                self,
                tree_name,
                None
            )

            if tree is not None:
                for item in tree.get_children():
                    tree.delete(item)

        if hasattr(self, "threat_hunt_results_notebook"):
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_hosts_frame,
                text="Hosts (0)"
            )
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_findings_frame,
                text="Findings (0)"
            )
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_packets_frame,
                text="Packets (0)"
            )
            self.threat_hunt_results_notebook.tab(
                self.threat_hunt_relationships_frame,
                text="Relationships (0)"
            )

        if hasattr(self, "threat_hunt_status_label"):
            self.threat_hunt_status_label.config(
                text=(
                    "Analyze a PCAP, then search by IP, domain, "
                    "destination port, protocol, or finding ID."
                )
            )

        if hasattr(self, "threat_hunt_summary_text"):
            self.set_text(
                self.threat_hunt_summary_text,
                (
                    "THREAT HUNT\n"
                    "===========\n\n"
                    "Analyze a PCAP, then search the indexed capture data."
                )
            )

        self.finding_records = []
        self.filtered_finding_records = []
        self.current_finding = None
        self.related_host_lookup = {}

        if hasattr(self, "finding_tree"):
            for item in self.finding_tree.get_children():
                self.finding_tree.delete(item)

        if hasattr(self, "finding_count_label"):
            self.finding_count_label.config(
                text="0 findings"
            )

        if hasattr(self, "selected_finding_label"):
            self.selected_finding_label.config(
                text="Select a finding"
            )

        if hasattr(self, "selected_finding_risk_label"):
            self.selected_finding_risk_label.config(
                text="-- / 100",
                foreground="#9ca3af"
            )

        if hasattr(self, "related_host_combo"):
            self.related_host_combo["values"] = []
            self.related_host_var.set("")

        if hasattr(self, "open_related_host_button"):
            self.open_related_host_button.config(
                state="disabled"
            )

        if hasattr(self, "add_finding_queue_button"):
            self.add_finding_queue_button.config(
                state="disabled"
            )

        if hasattr(self, "finding_detail_text"):
            self.set_text(
                self.finding_detail_text,
                ""
            )

        self.packet_evidence_records = []

        if hasattr(self, "packet_evidence_tree"):
            for item in self.packet_evidence_tree.get_children():
                self.packet_evidence_tree.delete(item)

        if hasattr(self, "finding_detail_notebook"):
            self.finding_detail_notebook.tab(
                self.packet_evidence_frame,
                text="Packet Evidence (0)"
            )

        if hasattr(self, "packet_detail_text"):
            self.set_text(
                self.packet_detail_text,
                ""
            )

        self.host_records = []
        self.filtered_host_records = []
        self.current_host = None

        if hasattr(self, "add_host_queue_button"):
            self.add_host_queue_button.config(
                state="disabled"
            )

        if hasattr(self, "host_tree"):
            for item in self.host_tree.get_children():
                self.host_tree.delete(item)

        if hasattr(self, "host_count_label"):
            self.host_count_label.config(text="0 hosts")

        if hasattr(self, "selected_host_label"):
            self.selected_host_label.config(
                text="Select a host"
            )

        if hasattr(self, "selected_host_risk_label"):
            self.selected_host_risk_label.config(
                text="-- / 100",
                foreground="#9ca3af"
            )

        if hasattr(self, "host_related_finding_combo"):
            self.host_related_finding_combo[
                "values"
            ] = []
            self.host_related_finding_var.set("")

        if hasattr(self, "open_host_finding_button"):
            self.open_host_finding_button.config(
                state="disabled"
            )

        self.set_text(
            self.host_detail_text,
            ""
        )

        for widget in [
            self.overview_tab,
            self.portscan_tab,
            self.dns_tab,
            self.outbound_tab,
            self.full_tab
        ]:
            self.set_text(
                widget,
                ""
            )

    def on_ai_provider_changed(self, event=None):
        provider = self.ai_provider_var.get().strip()

        if provider == "Local Ollama":
            if not self.analysis_running:
                self.ollama_model_entry.config(state="normal")
                self.test_local_ai_button.config(state="normal")

            self.options_note.config(
                text=(
                    "Local Ollama keeps AI prompts on this computer. "
                    "The model receives bounded structured findings and metadata, "
                    "not raw packet payloads."
                )
            )
        else:
            self.ollama_model_entry.config(state="disabled")
            self.test_local_ai_button.config(state="disabled")
            self.options_note.config(
                text=(
                    "OpenAI API uses the analyzer's existing optional cloud AI "
                    "integration and requires configured API access. Core PCAP "
                    "analysis works without AI."
                )
            )

    def call_ollama_chat(
        self,
        messages,
        model=None,
        timeout=180
    ):
        model_name = (
            model
            or self.ollama_model_var.get().strip()
            or DEFAULT_OLLAMA_MODEL
        )

        payload = {
            "model": model_name,
            "messages": messages,
            "stream": False,
            "keep_alive": "10m",
            "options": {
                "temperature": 0.2
            }
        }

        request = urllib.request.Request(
            OLLAMA_API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=timeout
            ) as response:
                response_text = response.read().decode(
                    "utf-8"
                )
        except urllib.error.HTTPError as error:
            try:
                detail = error.read().decode(
                    "utf-8",
                    errors="replace"
                )
            except Exception:
                detail = str(error)

            raise RuntimeError(
                f"Ollama returned HTTP {error.code}: {detail}"
            ) from error
        except urllib.error.URLError as error:
            reason = getattr(
                error,
                "reason",
                error
            )
            raise RuntimeError(
                "Could not connect to Ollama at "
                "http://127.0.0.1:11434. Make sure Ollama is running. "
                f"Details: {reason}"
            ) from error

        try:
            result = json.loads(response_text)
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "Ollama returned a response that was not valid JSON."
            ) from error

        message = result.get(
            "message",
            {}
        )
        content = str(
            message.get(
                "content",
                ""
            )
        ).strip()

        if not content:
            raise RuntimeError(
                "Ollama returned an empty response."
            )

        return content

    def start_local_ai_test(self):
        if self.analysis_running:
            return

        model = (
            self.ollama_model_var.get().strip()
            or DEFAULT_OLLAMA_MODEL
        )
        self.ollama_model_var.set(model)

        self.test_local_ai_button.config(
            state="disabled"
        )
        self.ollama_model_entry.config(
            state="disabled"
        )
        self.ollama_test_status_var.set(
            f"Testing {model}..."
        )

        worker = threading.Thread(
            target=self.run_local_ai_test_worker,
            args=(model,),
            daemon=True
        )
        worker.start()

    def run_local_ai_test_worker(self, model):
        try:
            response = self.call_ollama_chat(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are a concise defensive network security "
                            "assistant. Answer only the user's question."
                        )
                    },
                    {
                        "role": "user",
                        "content": (
                            "Reply with exactly one short sentence confirming "
                            "that local AI is ready to help explain defensive "
                            "PCAP analysis results."
                        )
                    }
                ],
                model=model,
                timeout=180
            )

            self.root.after(
                0,
                self.local_ai_test_finished,
                True,
                model,
                response
            )
        except Exception as error:
            self.root.after(
                0,
                self.local_ai_test_finished,
                False,
                model,
                str(error)
            )

    def local_ai_test_finished(
        self,
        success,
        model,
        detail
    ):
        if self.ai_provider_var.get() == "Local Ollama":
            self.ollama_model_entry.config(state="normal")
            self.test_local_ai_button.config(state="normal")

        if success:
            self.ollama_test_status_var.set(
                f"Local AI ready: {model}"
            )
            messagebox.showinfo(
                "Local AI Ready",
                (
                    f"Ollama responded successfully using {model}.\n\n"
                    f"{detail}"
                )
            )
        else:
            self.ollama_test_status_var.set(
                "Local AI test failed"
            )
            messagebox.showerror(
                "Local AI Test Failed",
                (
                    "The GUI could not get a response from Ollama.\n\n"
                    f"{detail}"
                )
            )

    def build_local_ai_analysis_prompt(self, report):
        summary = report.get(
            "summary",
            {}
        )

        investigation = report.get(
            "finding_investigation",
            {}
        )
        findings = investigation.get(
            "findings",
            []
        )

        finding_items = []
        for finding in findings[:12]:
            related_hosts = []
            for host in finding.get(
                "related_hosts",
                []
            )[:8]:
                if isinstance(host, dict):
                    related_hosts.append(
                        host.get("ip", "Unknown")
                    )
                else:
                    related_hosts.append(str(host))

            finding_items.append({
                "finding_id": finding.get("finding_id"),
                "type": finding.get("type"),
                "title": finding.get("title"),
                "risk_score": finding.get("risk_score"),
                "assessment": finding.get("assessment"),
                "confidence": finding.get("confidence"),
                "source": finding.get("source"),
                "target": finding.get("target"),
                "protocol": finding.get("protocol"),
                "destination_port": finding.get("destination_port"),
                "related_hosts": related_hosts,
                "indicators": finding.get("indicators", [])[:10],
                "summary": finding.get("summary")
            })

        flagged_hosts = []
        for host in sorted(
            report.get("hosts", []),
            key=lambda item: item.get("risk_score", 0),
            reverse=True
        ):
            if host.get("risk_score", 0) <= 0:
                continue

            flagged_hosts.append({
                "ip": host.get("ip"),
                "risk_score": host.get("risk_score"),
                "assessment": host.get("assessment"),
                "threat_categories": host.get("threat_categories", []),
                "packets_sent": host.get("packets_sent", 0),
                "packets_received": host.get("packets_received", 0)
            })

            if len(flagged_hosts) >= 10:
                break

        evidence = {
            "capture_summary": {
                "overall_risk_score": summary.get("overall_risk_score"),
                "overall_assessment": summary.get("overall_assessment"),
                "packets_analyzed": summary.get("packets_analyzed"),
                "threat_categories": summary.get("threat_categories", [])
            },
            "structured_findings": finding_items,
            "flagged_hosts": flagged_hosts
        }

        return (
            "Explain this completed defensive PCAP analysis using only the "
            "structured evidence below. Do not invent packet contents, malware "
            "families, attribution, or proof of compromise. Treat suspicious "
            "IPs, domains, and ports as indicators for review unless the evidence "
            "explicitly establishes more. Keep the answer concise and useful to "
            "a junior SOC analyst. Use three sections: Overall Summary, Key "
            "Evidence, and Defensive Review Next Steps. Do not provide offensive "
            "instructions.\n\n"
            + json.dumps(
                evidence,
                indent=2,
                default=str
            )
        )

    def generate_local_ai_analysis_explanation(
        self,
        report,
        model
    ):
        prompt = self.build_local_ai_analysis_prompt(
            report
        )

        return self.call_ollama_chat(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a defensive network security analyst assistant. "
                        "Explain supplied evidence accurately and conservatively. "
                        "Never claim compromise from behavioral indicators alone."
                    )
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            model=model,
            timeout=300
        )

    def start_analysis(self):
        if not self.selected_file:
            messagebox.showwarning(
                "No File Selected",
                "Please select a PCAP file first."
            )
            return

        if self.analysis_running:
            return

        self.analysis_running = True

        self.analysis_generate_ai = self.generate_ai_var.get()
        self.analysis_save_reports = self.save_reports_var.get()
        self.analysis_ai_provider = self.ai_provider_var.get().strip()
        self.analysis_ollama_model = (
            self.ollama_model_var.get().strip()
            or DEFAULT_OLLAMA_MODEL
        )
        self.ollama_model_var.set(
            self.analysis_ollama_model
        )

        self.status_label.config(
            text="Analyzing PCAP..."
        )

        self.analyze_button.config(
            state="disabled"
        )

        self.select_button.config(
            state="disabled"
        )

        self.ai_checkbox.config(
            state="disabled"
        )

        self.ai_provider_combo.config(
            state="disabled"
        )
        self.ollama_model_entry.config(
            state="disabled"
        )
        self.test_local_ai_button.config(
            state="disabled"
        )

        self.save_checkbox.config(
            state="disabled"
        )

        self.save_case_button.config(
            state="disabled"
        )

        self.load_case_button.config(
            state="disabled"
        )

        self.progress_bar.config(
            maximum=100,
            value=0
        )

        analysis_thread = threading.Thread(
            target=self.run_analysis_worker,
            daemon=True
        )

        analysis_thread.start()

    def run_analysis_worker(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            use_openai = (
                self.analysis_generate_ai
                and self.analysis_ai_provider == "OpenAI API"
            )

            report = analyze_pcap(
                str(self.selected_file),
                interactive=False,
                generate_ai=use_openai,
                save_reports=self.analysis_save_reports,
                progress_callback=self.handle_progress_update
            )

            if not report:
                raise ValueError(
                    "The analyzer did not return report data."
                )

            if (
                self.analysis_generate_ai
                and self.analysis_ai_provider == "Local Ollama"
            ):
                self.root.after(
                    0,
                    self.status_label.config,
                    {
                        "text": (
                            "Core analysis complete | Generating local AI "
                            f"explanation with {self.analysis_ollama_model}..."
                        )
                    }
                )

                try:
                    explanation = (
                        self.generate_local_ai_analysis_explanation(
                            report,
                            self.analysis_ollama_model
                        )
                    )

                    report["ai_explanation"] = {
                        "requested": True,
                        "generated": True,
                        "provider": "Local Ollama",
                        "model": self.analysis_ollama_model,
                        "text": explanation
                    }
                except Exception as ai_error:
                    report["ai_explanation"] = {
                        "requested": True,
                        "generated": False,
                        "provider": "Local Ollama",
                        "model": self.analysis_ollama_model,
                        "text": "",
                        "error": str(ai_error)
                    }

            self.root.after(
                0,
                self.analysis_finished,
                report
            )

        except Exception as error:
            self.root.after(
                0,
                self.analysis_failed,
                str(error)
            )

        finally:
            try:
                loop.close()
            except Exception:
                pass

    def handle_progress_update(
        self,
        processed_packets,
        total_packets
    ):
        self.root.after(
            0,
            self.update_progress_bar,
            processed_packets,
            total_packets
        )

    def update_progress_bar(
        self,
        processed_packets,
        total_packets
    ):
        if not total_packets or total_packets <= 0:
            return

        percent = min(
            100,
            (processed_packets / total_packets) * 100
        )

        self.progress_bar.config(
            value=percent
        )

        self.status_label.config(
            text=(
                f"Analyzing PCAP... "
                f"{processed_packets:,} / "
                f"{total_packets:,} packets "
                f"({percent:.0f}%)"
            )
        )

    def analysis_finished(self, report):
        self.report_data = report
        self.current_case_path = None
        self.current_case_metadata = None

        self.case_status_label.config(
            text="Unsaved investigation case"
        )

        self.progress_bar.config(value=100)

        self.display_results(report)

        ai_info = report.get("ai_explanation", {})
        export_info = report.get("report_export", {})

        status_parts = ["Analysis complete"]

        finding_info = report.get(
            "finding_investigation",
            {}
        )
        finding_count = finding_info.get(
            "total_findings",
            0
        )

        hosts = report.get(
            "hosts",
            []
        )
        suspicious_host_count = sum(
            1
            for host in hosts
            if host.get("risk_score", 0) > 0
        )

        status_parts.append(
            f"{finding_count} finding"
            + ("" if finding_count == 1 else "s")
        )

        status_parts.append(
            f"{suspicious_host_count} flagged host"
            + ("" if suspicious_host_count == 1 else "s")
        )

        if ai_info.get("requested"):
            if ai_info.get("generated"):
                status_parts.append("AI explanation generated")
            else:
                status_parts.append("AI explanation unavailable")

        if export_info.get("saved"):
            status_parts.append("reports saved")

        self.status_label.config(
            text=" | ".join(status_parts)
        )

        self.analysis_running = False

        self.analyze_button.config(
            state="normal"
        )

        self.select_button.config(
            state="normal"
        )

        self.ai_checkbox.config(
            state="normal"
        )

        self.ai_provider_combo.config(
            state="readonly"
        )
        self.on_ai_provider_changed()

        self.save_checkbox.config(
            state="normal"
        )

        self.save_case_button.config(
            state="normal"
        )

        self.load_case_button.config(
            state="normal"
        )

        if export_info.get("saved"):
            self.txt_report_path = export_info.get("txt_path")
            self.json_report_path = export_info.get("json_path")
            self.csv_report_path = export_info.get("csv_path")

            if self.txt_report_path:
                self.open_txt_button.config(state="normal")

            if self.json_report_path:
                self.open_json_button.config(state="normal")

            if self.csv_report_path:
                self.open_csv_button.config(state="normal")

            if (
                self.txt_report_path
                or self.json_report_path
                or self.csv_report_path
            ):
                self.open_folder_button.config(state="normal")

            messagebox.showinfo(
                "Reports Saved",
                "Security reports were saved successfully.\n\n"
                f"TXT:\n{export_info.get('txt_path')}\n\n"
                f"JSON:\n{export_info.get('json_path')}\n\n"
                f"Packet Evidence CSV:\n{export_info.get('csv_path')}"
            )

    def analysis_failed(self, error_message):
        self.progress_bar.config(value=0)

        self.status_label.config(
            text="Analysis failed"
        )

        self.analysis_running = False

        self.analyze_button.config(
            state="normal"
        )

        self.select_button.config(
            state="normal"
        )

        self.ai_checkbox.config(
            state="normal"
        )

        self.ai_provider_combo.config(
            state="readonly"
        )
        self.on_ai_provider_changed()

        self.save_checkbox.config(
            state="normal"
        )

        self.save_case_button.config(
            state=(
                "normal"
                if self.report_data
                else "disabled"
            )
        )

        self.load_case_button.config(
            state="normal"
        )

        messagebox.showerror(
            "Analysis Error",
            "An error occurred while analyzing the PCAP:\n\n"
            f"{error_message}"
        )

    def open_path(self, path, item_name):
        if not path:
            messagebox.showwarning(
                "File Unavailable",
                f"No {item_name} is available yet."
            )
            return

        path = Path(path)

        if not path.exists():
            messagebox.showerror(
                "File Not Found",
                f"The {item_name} could not be found:\n\n{path}"
            )
            return

        try:
            os.startfile(str(path))
        except Exception as error:
            messagebox.showerror(
                "Open Error",
                f"Could not open the {item_name}:\n\n{error}"
            )

    def open_txt_report(self):
        self.open_path(
            self.txt_report_path,
            "TXT report"
        )

    def open_json_report(self):
        self.open_path(
            self.json_report_path,
            "JSON report"
        )

    def open_csv_report(self):
        self.open_path(
            self.csv_report_path,
            "packet evidence CSV"
        )

    def open_report_folder(self):
        report_path = (
            self.txt_report_path
            or self.json_report_path
            or self.csv_report_path
        )

        if not report_path:
            messagebox.showwarning(
                "Folder Unavailable",
                "No saved report folder is available yet."
            )
            return

        folder = Path(report_path).parent

        if not folder.exists():
            messagebox.showerror(
                "Folder Not Found",
                f"The report folder could not be found:\n\n{folder}"
            )
            return

        try:
            os.startfile(str(folder))
        except Exception as error:
            messagebox.showerror(
                "Open Error",
                f"Could not open the report folder:\n\n{error}"
            )

    def display_results(self, report):
        summary = report.get(
            "summary",
            {}
        )

        score = summary.get(
            "overall_risk_score",
            0
        )

        assessment = summary.get(
            "overall_assessment",
            "UNKNOWN"
        )

        packets = summary.get(
            "packets_analyzed",
            0
        )

        categories = summary.get(
            "threat_categories",
            []
        )

        assessment_color = self.get_assessment_color(
            assessment
        )

        self.assessment_card.config(
            text=assessment,
            foreground=assessment_color
        )

        self.score_card.config(
            text=f"{score} / 100",
            foreground=assessment_color
        )

        self.packet_card.config(
            text=f"{packets:,}"
        )

        if categories:
            self.categories_label.config(
                text="  •  ".join(categories)
            )
        else:
            self.categories_label.config(
                text="None detected"
            )

        self.display_overview(report)
        self.display_port_scans(report)
        self.display_dns(report)
        self.display_outbound(report)
        self.initialize_threat_hunt(report)
        self.display_findings(report)
        self.display_visuals(report)
        self.display_hosts(report)
        self.display_full_analysis(report)

    def get_assessment_color(self, assessment):
        assessment = assessment.upper()

        if assessment == "HIGH RISK":
            return "#f87171"

        if assessment == "SUSPICIOUS":
            return "#fbbf24"

        if assessment == "REVIEW RECOMMENDED":
            return "#facc15"

        if assessment == "LIKELY NORMAL":
            return "#4ade80"

        return "#f9fafb"

    def display_overview(self, report):
        summary = report.get(
            "summary",
            {}
        )

        lines = [
            "ANALYSIS OVERVIEW",
            "=" * 65,
            "",
            f"PCAP: {self.selected_file.name}",
            "",
            f"Overall Risk Score: "
            f"{summary.get('overall_risk_score', 0)}/100",
            "",
            f"Overall Assessment: "
            f"{summary.get('overall_assessment', 'UNKNOWN')}",
            "",
            f"Packets Analyzed: "
            f"{summary.get('packets_analyzed', 0):,}",
            "",
            f"IPv4 Packets: "
            f"{summary.get('ipv4_packets', 0):,}",
            "",
            f"IPv6 Packets: "
            f"{summary.get('ipv6_packets', 0):,}",
            "",
            "Threat Categories:"
        ]

        categories = summary.get(
            "threat_categories",
            []
        )

        if categories:
            for category in categories:
                lines.append(
                    f"  • {category}"
                )
        else:
            lines.append(
                "  None detected"
            )

        lines.append("")
        lines.append("Automated Explanation:")
        lines.append("-" * 65)

        explanation = report.get(
            "automated_explanation",
            []
        )

        if explanation:
            for line in explanation:
                lines.append(line)
        else:
            lines.append(
                "No automated explanation available."
            )

        lines.append("")
        lines.append("AI Analyst Explanation:")
        lines.append("-" * 65)

        ai_info = report.get("ai_explanation", {})

        if ai_info.get("generated") and ai_info.get("text"):
            provider = ai_info.get("provider")
            model = ai_info.get("model")

            if provider or model:
                lines.append(
                    "Provider: "
                    + str(provider or "Unknown")
                    + (
                        f" | Model: {model}"
                        if model
                        else ""
                    )
                )
                lines.append("")

            lines.append(ai_info.get("text"))
        elif ai_info.get("requested"):
            lines.append(
                "AI explanation was requested but could not be generated. "
                "The built-in analysis above is still available."
            )

            if ai_info.get("error"):
                lines.append("")
                lines.append(
                    f"AI error: {ai_info.get('error')}"
                )
        else:
            lines.append("AI explanation was not requested.")

        lines.append("")
        lines.append("Report Export:")
        lines.append("-" * 65)

        export_info = report.get("report_export", {})

        if export_info.get("saved"):
            lines.append("TXT report:")
            lines.append(f"  {export_info.get('txt_path')}")
            lines.append("")
            lines.append("JSON report:")
            lines.append(f"  {export_info.get('json_path')}")
            lines.append("")
            lines.append("Packet evidence CSV:")
            lines.append(f"  {export_info.get('csv_path')}")
        else:
            lines.append("Report files were not saved.")

        self.set_text(
            self.overview_tab,
            "\n".join(lines)
        )

    def display_port_scans(self, report):
        scans = report.get(
            "port_scans",
            []
        )

        lines = [
            "PORT SCAN FINDINGS",
            "=" * 65,
            ""
        ]

        if not scans:
            lines.append(
                "No obvious port scans detected."
            )

        else:
            for number, scan in enumerate(
                scans,
                start=1
            ):
                lines.extend([
                    f"Scan #{number}",
                    "-" * 65,
                    f"Source: {scan.get('source')}",
                    f"Target: {scan.get('target')}",
                    (
                        "Service/registered ports contacted: "
                        f"{scan.get('service_ports')}"
                    ),
                    (
                        "Total destination ports: "
                        f"{scan.get('total_destination_ports')}"
                    ),
                    (
                        "TCP SYN attempts: "
                        f"{scan.get('tcp_syn_attempts')}"
                    ),
                    (
                        "Duration: "
                        f"{scan.get('duration_seconds')} seconds"
                    ),
                    (
                        "Service ports/sec: "
                        f"{scan.get('service_ports_per_second')}"
                    ),
                    (
                        "Confidence: "
                        f"{scan.get('confidence')}"
                    ),
                    ""
                ])

        self.set_text(
            self.portscan_tab,
            "\n".join(lines)
        )

    def display_dns(self, report):
        dns = report.get(
            "dns",
            {}
        )

        lines = [
            "DNS ANALYSIS",
            "=" * 65,
            "",
            (
                "Total DNS Queries: "
                f"{dns.get('total_queries', 0):,}"
            ),
            (
                "Unique Domains: "
                f"{dns.get('unique_domains', 0):,}"
            ),
            (
                "Unique Domain Ratio: "
                f"{dns.get('unique_domain_ratio_percent', 0)}%"
            ),
            (
                "DNS Behavior Score: "
                f"{dns.get('behavior_score', 0)}/100"
            ),
            ""
        ]

        if dns.get("suspicious", False):
            lines.append(
                "Assessment: SUSPICIOUS DNS BEHAVIOR"
            )

            indicators = dns.get(
                "indicators",
                []
            )

            if indicators:
                lines.append("")
                lines.append("Indicators:")

                for indicator in indicators:
                    lines.append(
                        f"  • {indicator}"
                    )
        else:
            lines.append(
                "Assessment: No strong suspicious DNS behavior detected"
            )

        top_domains = dns.get(
            "top_domains",
            []
        )

        if top_domains:
            lines.append("")
            lines.append("Most Requested Domains:")
            lines.append("-" * 65)

            for item in top_domains:
                lines.append(
                    f"{item.get('domain')}: "
                    f"{item.get('queries')} queries"
                )

        self.set_text(
            self.dns_tab,
            "\n".join(lines)
        )

    def display_outbound(self, report):
        findings = report.get(
            "correlated_outbound_activity",
            []
        )

        lines = [
            "CORRELATED OUTBOUND ACTIVITY",
            "=" * 65,
            ""
        ]

        if not findings:
            lines.append(
                "No strong correlated repeated outbound patterns detected."
            )

        else:
            for number, finding in enumerate(
                findings,
                start=1
            ):
                lines.extend([
                    f"Finding #{number}",
                    "-" * 65,
                    f"Source: {finding.get('source')}",
                    (
                        "Destination Port: "
                        f"{finding.get('destination_port')}"
                    ),
                    (
                        "TCP SYN Attempts: "
                        f"{finding.get('tcp_syn_attempts'):,}"
                    ),
                    (
                        "External Destinations: "
                        f"{finding.get('external_destinations')}"
                    ),
                    (
                        "Duration: "
                        f"{finding.get('duration_seconds')} seconds"
                    ),
                    (
                        "Average Interval: "
                        f"{finding.get('average_interval_seconds')} seconds"
                    ),
                    (
                        "Behavior Score: "
                        f"{finding.get('behavior_score')}/100"
                    ),
                    (
                        "Confidence: "
                        f"{finding.get('confidence')}"
                    )
                ])

                indicators = finding.get(
                    "indicators",
                    []
                )

                if indicators:
                    lines.append("Indicators:")

                    for indicator in indicators:
                        lines.append(
                            f"  • {indicator}"
                        )

                lines.append("")

        self.set_text(
            self.outbound_tab,
            "\n".join(lines)
        )

    def display_full_analysis(self, report):
        lines = []

        lines.append("FULL ANALYSIS")
        lines.append("=" * 65)
        lines.append("")

        summary = report.get(
            "summary",
            {}
        )

        lines.append("TRAFFIC SUMMARY")
        lines.append("-" * 65)

        lines.append(
            f"Packets analyzed: "
            f"{summary.get('packets_analyzed', 0):,}"
        )

        lines.append(
            f"IPv4 packets: "
            f"{summary.get('ipv4_packets', 0):,}"
        )

        lines.append(
            f"IPv6 packets: "
            f"{summary.get('ipv6_packets', 0):,}"
        )

        protocols = summary.get(
            "protocols",
            {}
        )

        if protocols:
            lines.append("")
            lines.append("Protocols:")

            for protocol, count in sorted(
                protocols.items(),
                key=lambda item: item[1],
                reverse=True
            ):
                lines.append(
                    f"  {protocol}: {count:,}"
                )

        lines.append("")
        lines.append("GENERIC BEHAVIOR FINDINGS")
        lines.append("-" * 65)

        generic_findings = report.get(
            "generic_behavior_findings",
            []
        )

        if generic_findings:
            for number, finding in enumerate(
                generic_findings,
                start=1
            ):
                lines.extend([
                    "",
                    f"Finding #{number}",
                    (
                        f"{finding.get('endpoint_1')} <-> "
                        f"{finding.get('endpoint_2')}"
                    ),
                    (
                        f"Protocol: "
                        f"{finding.get('protocol')}"
                    ),
                    (
                        f"Risk Score: "
                        f"{finding.get('risk_score')}/100"
                    ),
                    (
                        f"Assessment: "
                        f"{finding.get('assessment')}"
                    ),
                    (
                        f"Packets: "
                        f"{finding.get('packets'):,}"
                    )
                ])

                indicators = finding.get(
                    "indicators",
                    []
                )

                if indicators:
                    for indicator in indicators:
                        lines.append(
                            f"  • {indicator}"
                        )
        else:
            lines.append(
                "No significant generic behavioral anomalies detected."
            )

        lines.append("")
        lines.append("")
        lines.append("TOP NETWORK CONVERSATIONS")
        lines.append("-" * 65)

        conversations = report.get(
            "top_network_conversations",
            []
        )

        if conversations:
            for number, conversation in enumerate(
                conversations,
                start=1
            ):
                lines.extend([
                    "",
                    f"Conversation #{number}",
                    (
                        f"{conversation.get('endpoint_1')} <-> "
                        f"{conversation.get('endpoint_2')}"
                    ),
                    (
                        f"Protocol: "
                        f"{conversation.get('protocol')}"
                    ),
                    (
                        f"Packets: "
                        f"{conversation.get('packets'):,}"
                    ),
                    (
                        f"Bytes: "
                        f"{conversation.get('bytes'):,}"
                    ),
                    (
                        f"Duration: "
                        f"{conversation.get('duration_seconds')} seconds"
                    ),
                    (
                        f"Packets/sec: "
                        f"{conversation.get('packets_per_second')}"
                    )
                ])
        else:
            lines.append(
                "No conversation data available."
            )

        self.set_text(
            self.full_tab,
            "\n".join(lines)
        )

    def set_text(self, widget, content):
        widget.config(
            state="normal"
        )

        widget.delete(
            "1.0",
            tk.END
        )

        widget.insert(
            "1.0",
            content
        )

        widget.config(
            state="disabled"
        )

        widget.see(
            "1.0"
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = PCAPAnalyzerGUI(root)
    root.mainloop()