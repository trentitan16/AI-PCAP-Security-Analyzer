import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
import threading
import asyncio

from analyzer import analyze_pcap


class PCAPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI PCAP Security Analyzer")
        self.root.geometry("950x740")
        self.root.minsize(850, 620)

        self.selected_file = None
        self.report_data = None
        self.analysis_running = False

        self.build_interface()

    def build_interface(self):
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill="both", expand=True)

        title = ttk.Label(
            main_frame,
            text="AI PCAP Security Analyzer",
            font=("Segoe UI", 22, "bold")
        )
        title.pack(pady=(0, 5))

        subtitle = ttk.Label(
            main_frame,
            text="Defensive network traffic analysis for PCAP files",
            font=("Segoe UI", 11)
        )
        subtitle.pack(pady=(0, 20))

        file_frame = ttk.LabelFrame(
            main_frame,
            text="PCAP File",
            padding=12
        )
        file_frame.pack(fill="x", pady=(0, 15))

        self.file_label = ttk.Label(
            file_frame,
            text="No PCAP file selected",
            font=("Segoe UI", 10)
        )
        self.file_label.pack(side="left", fill="x", expand=True)

        self.select_button = ttk.Button(
            file_frame,
            text="Select PCAP",
            command=self.select_pcap
        )
        self.select_button.pack(side="right", padx=(10, 0))

        self.analyze_button = ttk.Button(
            main_frame,
            text="Analyze PCAP",
            command=self.start_analysis,
            state="disabled"
        )
        self.analyze_button.pack(pady=(0, 12))

        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill="x", pady=(0, 15))

        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode="indeterminate"
        )
        self.progress_bar.pack(fill="x")

        self.status_label = ttk.Label(
            main_frame,
            text="Ready",
            font=("Segoe UI", 10)
        )
        self.status_label.pack(pady=(0, 15))

        summary_frame = ttk.LabelFrame(
            main_frame,
            text="Overall Assessment",
            padding=15
        )
        summary_frame.pack(fill="x", pady=(0, 15))

        summary_inner = ttk.Frame(summary_frame)
        summary_inner.pack(fill="x")

        assessment_frame = ttk.Frame(summary_inner)
        assessment_frame.pack(side="left", expand=True, fill="both")

        ttk.Label(
            assessment_frame,
            text="Assessment",
            font=("Segoe UI", 10)
        ).pack()

        self.assessment_label = ttk.Label(
            assessment_frame,
            text="Not Analyzed",
            font=("Segoe UI", 18, "bold")
        )
        self.assessment_label.pack(pady=5)

        score_frame = ttk.Frame(summary_inner)
        score_frame.pack(side="left", expand=True, fill="both")

        ttk.Label(
            score_frame,
            text="Risk Score",
            font=("Segoe UI", 10)
        ).pack()

        self.score_label = ttk.Label(
            score_frame,
            text="-- / 100",
            font=("Segoe UI", 18, "bold")
        )
        self.score_label.pack(pady=5)

        packet_frame = ttk.Frame(summary_inner)
        packet_frame.pack(side="left", expand=True, fill="both")

        ttk.Label(
            packet_frame,
            text="Packets Analyzed",
            font=("Segoe UI", 10)
        ).pack()

        self.packet_label = ttk.Label(
            packet_frame,
            text="--",
            font=("Segoe UI", 18, "bold")
        )
        self.packet_label.pack(pady=5)

        categories_frame = ttk.LabelFrame(
            main_frame,
            text="Threat Categories",
            padding=12
        )
        categories_frame.pack(fill="x", pady=(0, 15))

        self.categories_label = ttk.Label(
            categories_frame,
            text="None",
            font=("Segoe UI", 10),
            wraplength=850,
            justify="left"
        )
        self.categories_label.pack(anchor="w")

        findings_frame = ttk.LabelFrame(
            main_frame,
            text="Key Findings",
            padding=10
        )
        findings_frame.pack(
            fill="both",
            expand=True,
            pady=(0, 10)
        )

        text_container = ttk.Frame(findings_frame)
        text_container.pack(fill="both", expand=True)

        scrollbar = ttk.Scrollbar(
            text_container,
            orient="vertical"
        )
        scrollbar.pack(side="right", fill="y")

        self.results_text = tk.Text(
            text_container,
            wrap="word",
            height=16,
            font=("Consolas", 10),
            yscrollcommand=scrollbar.set,
            state="disabled"
        )
        self.results_text.pack(
            side="left",
            fill="both",
            expand=True
        )

        scrollbar.config(
            command=self.results_text.yview
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
        self.assessment_label.config(
            text="Not Analyzed"
        )

        self.score_label.config(
            text="-- / 100"
        )

        self.packet_label.config(
            text="--"
        )

        self.categories_label.config(
            text="None"
        )

        self.results_text.config(
            state="normal"
        )

        self.results_text.delete(
            "1.0",
            tk.END
        )

        self.results_text.config(
            state="disabled"
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

        self.status_label.config(
            text="Analyzing PCAP..."
        )

        self.analyze_button.config(
            state="disabled"
        )

        self.select_button.config(
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
                interactive=False
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

        self.display_results(
            self.report_data
        )

        self.status_label.config(
            text="Analysis complete"
        )

        self.analysis_running = False

        self.analyze_button.config(
            state="normal"
        )

        self.select_button.config(
            state="normal"
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

        messagebox.showerror(
            "Analysis Error",
            "An error occurred while analyzing the PCAP:\n\n"
            f"{error_message}"
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

        self.score_label.config(
            text=f"{score} / 100"
        )

        self.assessment_label.config(
            text=assessment
        )

        self.packet_label.config(
            text=f"{packets:,}"
        )

        if categories:
            category_text = " | ".join(
                categories
            )
        else:
            category_text = "None detected"

        self.categories_label.config(
            text=category_text
        )

        lines = []

        lines.append("ANALYSIS SUMMARY")
        lines.append("=" * 60)
        lines.append(
            f"PCAP: {self.selected_file.name}"
        )
        lines.append(
            f"Overall Risk Score: {score}/100"
        )
        lines.append(
            f"Overall Assessment: {assessment}"
        )
        lines.append(
            f"Packets Analyzed: {packets:,}"
        )

        lines.append("")
        lines.append("PORT SCAN FINDINGS")
        lines.append("=" * 60)

        port_scans = report.get(
            "port_scans",
            []
        )

        if port_scans:
            for number, scan in enumerate(
                port_scans[:5],
                start=1
            ):
                lines.append(
                    f"Scan #{number}"
                )
                lines.append(
                    f"Source: {scan.get('source')}"
                )
                lines.append(
                    f"Target: {scan.get('target')}"
                )
                lines.append(
                    "Service/registered ports contacted: "
                    f"{scan.get('service_ports')}"
                )
                lines.append(
                    "Total destination ports: "
                    f"{scan.get('total_destination_ports')}"
                )
                lines.append(
                    "TCP SYN attempts: "
                    f"{scan.get('tcp_syn_attempts')}"
                )
                lines.append(
                    "Duration: "
                    f"{scan.get('duration_seconds')} seconds"
                )
                lines.append(
                    "Confidence: "
                    f"{scan.get('confidence')}"
                )
                lines.append("")
        else:
            lines.append(
                "No obvious port scans detected."
            )

        lines.append("")
        lines.append("DNS ANALYSIS")
        lines.append("=" * 60)

        dns = report.get(
            "dns",
            {}
        )

        lines.append(
            "Total DNS Queries: "
            f"{dns.get('total_queries', 0):,}"
        )

        lines.append(
            "Unique Domains: "
            f"{dns.get('unique_domains', 0):,}"
        )

        lines.append(
            "Unique Domain Ratio: "
            f"{dns.get('unique_domain_ratio_percent', 0)}%"
        )

        lines.append(
            "DNS Behavior Score: "
            f"{dns.get('behavior_score', 0)}/100"
        )

        if dns.get("suspicious", False):
            lines.append(
                "Assessment: SUSPICIOUS DNS BEHAVIOR"
            )

            indicators = dns.get(
                "indicators",
                []
            )

            if indicators:
                lines.append("Indicators:")

                for indicator in indicators:
                    lines.append(
                        f"  - {indicator}"
                    )
        else:
            lines.append(
                "Assessment: No strong suspicious DNS behavior detected"
            )

        lines.append("")
        lines.append(
            "CORRELATED OUTBOUND ACTIVITY"
        )
        lines.append("=" * 60)

        outbound = report.get(
            "correlated_outbound_activity",
            []
        )

        if outbound:
            for number, finding in enumerate(
                outbound[:5],
                start=1
            ):
                lines.append(
                    f"Finding #{number}"
                )
                lines.append(
                    f"Source: {finding.get('source')}"
                )
                lines.append(
                    "Destination Port: "
                    f"{finding.get('destination_port')}"
                )
                lines.append(
                    "TCP SYN Attempts: "
                    f"{finding.get('tcp_syn_attempts'):,}"
                )
                lines.append(
                    "External Destinations: "
                    f"{finding.get('external_destinations')}"
                )
                lines.append(
                    "Behavior Score: "
                    f"{finding.get('behavior_score')}/100"
                )
                lines.append(
                    "Confidence: "
                    f"{finding.get('confidence')}"
                )

                indicators = finding.get(
                    "indicators",
                    []
                )

                if indicators:
                    lines.append("Indicators:")

                    for indicator in indicators:
                        lines.append(
                            f"  - {indicator}"
                        )

                lines.append("")
        else:
            lines.append(
                "No strong correlated repeated outbound patterns detected."
            )

        lines.append("")
        lines.append("AUTOMATED EXPLANATION")
        lines.append("=" * 60)

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

        self.results_text.config(
            state="normal"
        )

        self.results_text.delete(
            "1.0",
            tk.END
        )

        self.results_text.insert(
            "1.0",
            "\n".join(lines)
        )

        self.results_text.config(
            state="disabled"
        )

        self.results_text.see("1.0")


if __name__ == "__main__":
    root = tk.Tk()
    app = PCAPAnalyzerGUI(root)
    root.mainloop()