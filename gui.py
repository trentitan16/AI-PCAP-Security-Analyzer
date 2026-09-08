import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import threading
import asyncio
import os

from analyzer import analyze_pcap


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

        self.generate_ai_var = tk.BooleanVar(value=False)
        self.save_reports_var = tk.BooleanVar(value=False)

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
            text="GUI v1.3 Development",
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

        self.ai_checkbox = ttk.Checkbutton(
            options_inner,
            text="Generate AI Explanation",
            variable=self.generate_ai_var,
            style="Option.TCheckbutton"
        )
        self.ai_checkbox.pack(side="left")

        self.save_checkbox = ttk.Checkbutton(
            options_inner,
            text="Save TXT + JSON Reports",
            variable=self.save_reports_var,
            style="Option.TCheckbutton"
        )
        self.save_checkbox.pack(side="left", padx=(18, 0))

        options_note = ttk.Label(
            options_card,
            text=(
                "AI is optional and requires configured OpenAI API access. "
                "Core PCAP analysis works without it."
            ),
            style="CardMuted.TLabel"
        )
        options_note.pack(anchor="w", pady=(7, 0))

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

        self.finding_tab = self.create_finding_investigation_tab()

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
            width=88,
            minwidth=78,
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
            width=210,
            minwidth=160,
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

        self.finding_detail_text = tk.Text(
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
        self.finding_detail_text.pack(
            side="left",
            fill="both",
            expand=True
        )

        detail_scrollbar.config(
            command=self.finding_detail_text.yview
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

    def show_host_details(self, host):
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
        self.progress_bar.config(value=0)
        self.txt_report_path = None
        self.json_report_path = None

        self.open_txt_button.config(state="disabled")
        self.open_json_button.config(state="disabled")
        self.open_folder_button.config(state="disabled")

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

        if hasattr(self, "finding_detail_text"):
            self.set_text(
                self.finding_detail_text,
                ""
            )

        self.host_records = []
        self.filtered_host_records = []

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

        self.save_checkbox.config(
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
            report = analyze_pcap(
                str(self.selected_file),
                interactive=False,
                generate_ai=self.analysis_generate_ai,
                save_reports=self.analysis_save_reports,
                progress_callback=self.handle_progress_update
            )

            if not report:
                raise ValueError(
                    "The analyzer did not return report data."
                )

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

        self.save_checkbox.config(
            state="normal"
        )

        if export_info.get("saved"):
            self.txt_report_path = export_info.get("txt_path")
            self.json_report_path = export_info.get("json_path")

            if self.txt_report_path:
                self.open_txt_button.config(state="normal")

            if self.json_report_path:
                self.open_json_button.config(state="normal")

            if self.txt_report_path or self.json_report_path:
                self.open_folder_button.config(state="normal")

            messagebox.showinfo(
                "Reports Saved",
                "Security reports were saved successfully.\n\n"
                f"TXT:\n{export_info.get('txt_path')}\n\n"
                f"JSON:\n{export_info.get('json_path')}"
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

        self.save_checkbox.config(
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

    def open_report_folder(self):
        report_path = (
            self.txt_report_path
            or self.json_report_path
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
        self.display_findings(report)
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
            lines.append(ai_info.get("text"))
        elif ai_info.get("requested"):
            lines.append(
                "AI explanation was requested but could not be generated. "
                "The built-in analysis above is still available."
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