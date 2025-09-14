import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from heuristics import full_url_analysis


class BWScamScanGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("BWScamScan - Botswana URL Safety Analyzer")
        self.root.geometry("800x700")
        self.root.configure(bg='#f0f0f0')

        # Make the window resizable
        self.root.minsize(700, 600)

        # Configure style
        self.setup_styles()

        # Create main frame
        self.main_frame = ttk.Frame(root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights for resizing
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)

        # Create widgets
        self.create_widgets()

        # Analysis results storage
        self.current_results = None

    def setup_styles(self):
        style = ttk.Style()
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#2c3e50')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), foreground='#34495e')
        style.configure('RiskCritical.TLabel', font=('Arial', 14, 'bold'), foreground='#c0392b')
        style.configure('RiskHigh.TLabel', font=('Arial', 14, 'bold'), foreground='#e74c3c')
        style.configure('RiskMedium.TLabel', font=('Arial', 14, 'bold'), foreground='#f39c12')
        style.configure('RiskLow.TLabel', font=('Arial', 14, 'bold'), foreground='#27ae60')
        style.configure('Accent.TButton', font=('Arial', 10, 'bold'))

    def create_widgets(self):
        # Title
        title_label = ttk.Label(self.main_frame, text="🔍 BWScamScan - URL Safety Analyzer",
                                style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        # URL Input
        ttk.Label(self.main_frame, text="Enter suspicious URL:",
                  style='Header.TLabel').grid(row=1, column=0, sticky=tk.W, pady=(10, 5))

        self.url_entry = ttk.Entry(self.main_frame, width=60, font=('Arial', 10))
        self.url_entry.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))
        self.url_entry.insert(0, "https://")

        # Company Input
        ttk.Label(self.main_frame, text="Which company is this link claiming to be from?",
                  style='Header.TLabel').grid(row=3, column=0, sticky=tk.W, pady=(10, 5))

        self.company_entry = ttk.Entry(self.main_frame, width=40, font=('Arial', 10))
        self.company_entry.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))
        self.company_entry.insert(0, "e.g., Orange, FNB, Mascom")

        # Analyze Button
        self.analyze_button = ttk.Button(self.main_frame, text="🔎 Analyze URL",
                                         command=self.start_analysis, style='Accent.TButton')
        self.analyze_button.grid(row=5, column=0, columnspan=2, pady=(10, 20))

        # Progress bar
        self.progress = ttk.Progressbar(self.main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 20))

        # Results Notebook (Tabbed interface)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        # Configure row weight for the notebook to expand
        self.main_frame.rowconfigure(7, weight=1)

        # Summary Tab
        self.summary_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.summary_frame, text="📊 Summary")

        # Warnings Tab
        self.warnings_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.warnings_frame, text="⚠️ Warnings")

        # Verification Tab
        self.verification_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.verification_frame, text="🔍 Verification")

        # Initialize results areas
        self.setup_results_areas()

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to analyze URLs")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=1, column=0, sticky=(tk.W, tk.E))

    def setup_results_areas(self):
        # Summary Tab
        self.summary_text = scrolledtext.ScrolledText(self.summary_frame, wrap=tk.WORD,
                                                      height=15, font=('Arial', 10))
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        self.summary_text.config(state=tk.DISABLED)

        # Warnings Tab
        self.warnings_text = scrolledtext.ScrolledText(self.warnings_frame, wrap=tk.WORD,
                                                       height=15, font=('Arial', 10))
        self.warnings_text.pack(fill=tk.BOTH, expand=True)
        self.warnings_text.config(state=tk.DISABLED)

        # Verification Tab
        self.verification_text = scrolledtext.ScrolledText(self.verification_frame, wrap=tk.WORD,
                                                           height=15, font=('Arial', 10))
        self.verification_text.pack(fill=tk.BOTH, expand=True)
        self.verification_text.config(state=tk.DISABLED)

    def start_analysis(self):
        url = self.url_entry.get().strip()
        company = self.company_entry.get().strip()

        # Basic validation
        if not url or url == "https://":
            messagebox.showwarning("Input Error", "Please enter a URL to analyze.")
            return

        if not company or company == "e.g., Orange, FNB, Mascom":
            messagebox.showwarning("Input Error", "Please specify which company this link claims to be from.")
            return

        # Disable button and show progress
        self.analyze_button.config(state=tk.DISABLED)
        self.progress.start()
        self.status_var.set("Analyzing URL...")

        # Run analysis in separate thread to prevent GUI freezing
        thread = threading.Thread(target=self.run_analysis, args=(url, company))
        thread.daemon = True
        thread.start()

    def run_analysis(self, url, company):
        try:
            # This is the actual analysis from our heuristics module
            results = full_url_analysis(url, company)
            self.current_results = results

            # Update GUI in the main thread
            self.root.after(0, self.display_results, results)

        except Exception as e:
            self.root.after(0, self.analysis_failed, str(e))
        finally:
            self.root.after(0, self.analysis_complete)

    def display_results(self, results):
        # Clear previous results
        for widget in [self.summary_text, self.warnings_text, self.verification_text]:
            widget.config(state=tk.NORMAL)
            widget.delete(1.0, tk.END)

        # Display Summary
        self.summary_text.insert(tk.END, "📋 ANALYSIS SUMMARY\n")
        self.summary_text.insert(tk.END, "=" * 50 + "\n\n")
        self.summary_text.insert(tk.END, f"Original URL: {results['original_url']}\n")
        if results['final_url'] != results['original_url']:
            self.summary_text.insert(tk.END, f"Final URL (after redirect): {results['final_url']}\n")
        self.summary_text.insert(tk.END, f"\nTotal Risk Score: {results['total_score']}/10+\n")

        # Color-coded risk category
        risk_category = results['risk_category']
        risk_text = f"Risk Category: {risk_category}\n\n"

        if risk_category == "CRITICAL":
            risk_text = f"Risk Category: 🚨 {risk_category} 🚨\n\n"
        elif risk_category == "High":
            risk_text = f"Risk Category: ⚠️ {risk_category} ⚠️\n\n"
        elif risk_category == "Medium":
            risk_text = f"Risk Category: 🔶 {risk_category} 🔶\n\n"
        else:
            risk_text = f"Risk Category: ✅ {risk_category} ✅\n\n"

        self.summary_text.insert(tk.END, risk_text)

        # Safe Browsing result
        if results['safe_browsing']['score'] > 0:
            self.summary_text.insert(tk.END, "🔒 Safe Browsing: ❌ BLACKLISTED\n")
        else:
            self.summary_text.insert(tk.END, "🔒 Safe Browsing: ✅ Not in known threat databases\n")

        self.summary_text.config(state=tk.DISABLED)

        # Display Warnings
        self.warnings_text.insert(tk.END, "⚠️ DETECTED WARNINGS\n")
        self.warnings_text.insert(tk.END, "=" * 50 + "\n\n")

        # Safe Browsing warning (if any)
        if results['safe_browsing']['warning']:
            self.warnings_text.insert(tk.END, "🔴 " + results['safe_browsing']['warning'] + "\n\n")

        # Heuristic warnings
        if results['heuristics']['warnings']:
            for warning in results['heuristics']['warnings']:
                self.warnings_text.insert(tk.END, "🟠 " + warning + "\n\n")
        else:
            self.warnings_text.insert(tk.END, "✅ No heuristic warnings detected\n")

        self.warnings_text.config(state=tk.DISABLED)

        # Display Verification Steps
        self.verification_text.insert(tk.END, "🔍 MANUAL VERIFICATION STEPS\n")
        self.verification_text.insert(tk.END, "=" * 50 + "\n\n")

        # Get the clean URL from the results if it exists
        clean_url = results.get('verification_steps', {}).get('clean_search_url', results['final_url'])
        self.verification_text.insert(tk.END, f"🔗 URL to search for: {clean_url}\n\n")
        self.verification_text.insert(tk.END, results['verification_steps']['message'])
        self.verification_text.config(state=tk.DISABLED)

        # Select the most relevant tab automatically
        if results['safe_browsing']['score'] > 0 or results['heuristics']['warnings']:
            self.notebook.select(1)  # Show warnings tab
        else:
            self.notebook.select(2)  # Show verification tab for safe links

    def analysis_failed(self, error_msg):
        messagebox.showerror("Analysis Error", f"An error occurred during analysis:\n{error_msg}")
        self.status_var.set("Analysis failed")

    def analysis_complete(self):
        self.progress.stop()
        self.analyze_button.config(state=tk.NORMAL)
        self.status_var.set("Analysis complete")


def main():
    root = tk.Tk()
    app = BWScamScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()