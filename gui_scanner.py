#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import subprocess
import os
from datetime import datetime
import sys
import platform

class VulnScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Web Vulnerability Scanner - v4.0.0")
        self.root.geometry("1300x900")
        self.root.configure(bg='#0c0c0c')
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.scanning = False
        self.scan_process = None
        self.modules = {}
        
        self.create_header()
        self.create_main_frame()
        self.create_controls()
        self.create_output_area()
        self.create_status_bar()
        
    def configure_styles(self):
        system = platform.system()
        font_family = 'Monaco' if system == "Darwin" else 'Courier New'
        
        self.style.configure('Title.TLabel', foreground='#00ff41', background='#0c0c0c', font=(font_family, 18, 'bold'))
        self.style.configure('Header.TLabel', foreground='#ffffff', background='#0c0c0c', font=(font_family, 11))
        self.style.configure('Custom.TFrame', background='#1a1a1a')
        self.style.configure('Custom.TButton', background='#0078d4', foreground='white', font=(font_family, 10, 'bold'))
        self.style.configure('Success.TButton', background='#107c10', foreground='white')
        self.style.configure('Danger.TButton', background='#d13438', foreground='white')
        self.style.configure('TLabelframe', background='#1a1a1a', foreground='#00ff41')
        self.style.configure('TLabelframe.Label', background='#1a1a1a', foreground='#00ff41', font=(font_family, 10, 'bold'))

    def create_header(self):
        header = ttk.Frame(self.root, style='Custom.TFrame')
        header.pack(fill='x', padx=5, pady=5)
        ttk.Label(header, text="🛡️ SIMPLE WEB VULNERABILITY SCANNER", style='Title.TLabel').pack(pady=10)
        ttk.Label(header, text="Educational & Authorized Testing Framework v4.0.0", style='Header.TLabel').pack()

    def create_main_frame(self):
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill='both', expand=True, padx=5, pady=5)
        self.left_panel = ttk.Frame(self.main_frame, style='Custom.TFrame', width=350)
        self.left_panel.pack(side='left', fill='y', padx=(0, 5))
        self.left_panel.pack_propagate(False)
        self.right_panel = ttk.Frame(self.main_frame, style='Custom.TFrame')
        self.right_panel.pack(side='right', fill='both', expand=True)

    def create_controls(self):
        # Target
        t_frame = ttk.LabelFrame(self.left_panel, text="🎯 TARGET")
        t_frame.pack(fill='x', padx=10, pady=5)
        self.url_var = tk.StringVar(value="")
        ttk.Entry(t_frame, textvariable=self.url_var).pack(fill='x', padx=5, pady=5)

        # Modules
        m_frame = ttk.LabelFrame(self.left_panel, text="🔍 MODULES")
        m_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        canvas = tk.Canvas(m_frame, bg='#1a1a1a', highlightthickness=0)
        scrollbar = ttk.Scrollbar(m_frame, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas, style='Custom.TFrame')
        
        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        module_list = [
            ("XSS Detection", "xss"), ("SQL Injection", "sqli"), ("Dir Bruteforce", "directory"),
            ("Security Headers", "headers"), ("security.txt", "security_txt"), ("robots.txt", "robots_txt"),
            ("Subdomain Enum", "subdomain"), ("Command Inject", "command_injection"), ("LFI/RFI", "lfi_rfi"),
            ("SSRF", "ssrf"), ("CSRF", "csrf"), ("Webshell", "webshell"), ("Auth Security", "auth"),
            ("API Security", "api"), ("CORS", "cors"), ("Open Redirect", "open_redirect"),
            ("Sec Misconfig", "security_misconfig"), ("Access Control", "broken_access_control"),
            ("JWT Security", "jwt"), ("Proto Pollution", "proto_pollution"), ("Cloud Security", "cloud"),
            ("GraphQL", "graphql"),
            ("🔴 XXE Attack", "xxe"), ("🔴 SSTI (RCE)", "ssti"), ("🔴 Deserialization", "deserialization"),
            ("🔴 Race Condition", "race_condition"), ("🔍 Recon", "recon")
        ]

        for name, key in module_list:
            var = tk.BooleanVar(value=True if key in ["xss", "sqli", "headers"] else False)
            self.modules[key] = var
            ttk.Checkbutton(scroll_frame, text=name, variable=var).pack(anchor='w', padx=5)

        # Controls
        c_frame = ttk.Frame(self.left_panel, style='Custom.TFrame')
        c_frame.pack(fill='x', padx=10, pady=10)
        
        self.scan_btn = ttk.Button(c_frame, text="🚀 START SCAN", style='Custom.TButton', command=self.start_scan)
        self.scan_btn.pack(fill='x', pady=2)
        
        self.stop_btn = ttk.Button(c_frame, text="⏹️ STOP", style='Danger.TButton', command=self.stop_scan, state='disabled')
        self.stop_btn.pack(fill='x', pady=2)

    def create_output_area(self):
        self.output_text = scrolledtext.ScrolledText(self.right_panel, bg='#000000', fg='#00ff41', font=('Monaco', 10))
        self.output_text.pack(fill='both', expand=True)

    def create_status_bar(self):
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var, background='#0c0c0c', foreground='#ffffff').pack(side='bottom', anchor='w')

    def start_scan(self):
        url = self.url_var.get().strip()
        if not url: return
        
        selected = [k for k, v in self.modules.items() if v.get()]
        if not selected:
            messagebox.showwarning("Warning", "Select at least one module")
            return

        self.scanning = True
        self.scan_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        
        threading.Thread(target=self.run_process, args=(url, selected), daemon=True).start()

    def run_process(self, url, modules):
        # Map GUI module keys to scanner module IDs
        mapping = {
            'xss': 'xss_scanner',
            'sqli': 'sqli_scanner',
            'command_injection': 'cmd_injection',
            'lfi_rfi': 'lfi_scanner',
            'ssrf': 'ssrf_scanner',
            'csrf': 'csrf_scanner',
            'webshell': 'webshell_scanner',
            'auth': 'auth_scanner',
            'api': 'api_scanner',
            'subdomain': 'subdomain_scanner',
            'ssi': 'ssi_scanner',
            'cors': 'cors_scanner',
            'open_redirect': 'open_redirect',
            'security_misconfig': 'misconfig',
            'broken_access_control': 'broken_access_control',
            'jwt': 'jwt_scanner',
            'proto_pollution': 'proto_pollution',
            'cloud': 'cloud_scanner',
            'graphql': 'graphql_scanner',
            'directory': 'directory_scanner',
            'headers': 'headers_scanner',
            'security_txt': 'security_txt_scanner',
            'robots_txt': 'robots_scanner',
            'xxe': 'xxe_scanner',
            'ssti': 'ssti_scanner',
            'deserialization': 'deserialization',
            'race_condition': 'race_condition',
            'recon': 'recon_scanner'
        }
        mod_ids = [mapping.get(m, m) for m in modules]
        
        cmd = [sys.executable, "scanner.py", "-u", url, "-m", ",".join(mod_ids)]
        
        try:
            self.scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in iter(self.scan_process.stdout.readline, ''):
                if not self.scanning: break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
            self.scan_process.wait()
        except Exception as e:
            self.output_text.insert(tk.END, f"Error: {e}\n")
        finally:
            self.scanning = False
            self.root.after(0, lambda: [self.scan_btn.config(state='normal'), self.stop_btn.config(state='disabled')])

    def stop_scan(self):
        self.scanning = False
        if self.scan_process: self.scan_process.terminate()

if __name__ == "__main__":
    root = tk.Tk()
    app = VulnScannerGUI(root)
    root.mainloop()