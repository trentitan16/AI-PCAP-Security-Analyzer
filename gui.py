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
        main_frame = ttk.Frame(
            self.root,
            style="Main.TFrame",
            padding=20
        )
        main_frame.pack(fill="both", expand=True)

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
        controls_frame.pack(fill="x", pady=(0, 12))

        self.analyze_button = ttk.Button(
            controls_frame,
            text="Analyze PCAP",
            command=self.start_analysis,
            state="disabled",
            style="Primary.TButton"
        )
        self.analyze_button.pack(side="left")

        self.ai_checkbox = ttk.Checkbutton(
            controls_frame,
            text="Generate AI Explanation",
            variable=self.generate_ai_var,
            style="Option.TCheckbutton"
        )
        self.ai_checkbox.pack(
            side="left",
            padx=(18, 0)
        )

        self.save_checkbox = ttk.Checkbutton(
            controls_frame,
            text="Save Reports",
            variable=self.save_reports_var,
            style="Option.TCheckbutton"
        )
        self.save_checkbox.pack(
            side="left",
            padx=(14, 0)
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

        self.progress_bar = ttk.Progressbar(
            main_frame,
            mode="indeterminate"
        )
        self.progress_bar.pack(
            fill="x",
            pady=(0, 12)
        )

        report_controls = ttk.Frame(
            main_frame,
            style="Main.TFrame"
        )
        report_controls.pack(fill="x", pady=(0, 15))

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
            fill="both",
            expand=True
        )

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

        self.full_tab = self.create_text_tab(
            "Full Analysis"
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

        self.progress_bar.start(10)

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
                save_reports=self.analysis_save_reports
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

    def analysis_finished(self, report):
        self.report_data = report

        self.progress_bar.stop()

        self.display_results(report)

        ai_info = report.get("ai_explanation", {})
        export_info = report.get("report_export", {})

        status_parts = ["Analysis complete"]

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
        self.progress_bar.stop()

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