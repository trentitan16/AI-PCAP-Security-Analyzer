import tkinter as tk
from tkinter import filedialog, messagebox
from pathlib import Path

from analyzer import analyze_pcap


class PCAPAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("AI PCAP Security Analyzer")
        self.root.geometry("700x450")

        self.selected_file = None

        title = tk.Label(
            root,
            text="AI PCAP Security Analyzer",
            font=("Segoe UI", 20, "bold")
        )
        title.pack(pady=(30, 10))

        subtitle = tk.Label(
            root,
            text="Defensive network traffic analysis for PCAP files",
            font=("Segoe UI", 11)
        )
        subtitle.pack(pady=(0, 30))

        self.file_label = tk.Label(
            root,
            text="No PCAP file selected",
            wraplength=600,
            font=("Segoe UI", 10)
        )
        self.file_label.pack(pady=10)

        select_button = tk.Button(
            root,
            text="Select PCAP File",
            command=self.select_pcap,
            width=22,
            height=2
        )
        select_button.pack(pady=10)

        self.analyze_button = tk.Button(
            root,
            text="Analyze PCAP",
            command=self.run_analysis,
            width=22,
            height=2,
            state="disabled"
        )
        self.analyze_button.pack(pady=10)

        self.status_label = tk.Label(
            root,
            text="Ready",
            font=("Segoe UI", 10)
        )
        self.status_label.pack(pady=25)

    def select_pcap(self):
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
            text=f"Selected: {self.selected_file.name}"
        )

        self.analyze_button.config(state="normal")
        self.status_label.config(
            text="PCAP selected and ready to analyze"
        )

    def run_analysis(self):
        if not self.selected_file:
            messagebox.showwarning(
                "No File Selected",
                "Please select a PCAP file first."
            )
            return

        self.status_label.config(text="Analyzing PCAP...")
        self.analyze_button.config(state="disabled")
        self.root.update()

        try:
            analyze_pcap(str(self.selected_file))

            self.status_label.config(text="Analysis complete")

            messagebox.showinfo(
                "Analysis Complete",
                "PCAP analysis completed successfully.\n\n"
                "The results are currently displayed in the terminal."
            )

        except Exception as error:
            self.status_label.config(text="Analysis failed")

            messagebox.showerror(
                "Analysis Error",
                f"An error occurred while analyzing the PCAP:\n\n{error}"
            )

        finally:
            self.analyze_button.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = PCAPAnalyzerGUI(root)
    root.mainloop()