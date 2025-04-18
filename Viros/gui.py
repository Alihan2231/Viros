#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GUI module for Viros Mitm
Provides a professional user interface for the ARP spoofing detection tool.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, Toplevel
import threading
import os
import sys
import time
import logging
import webbrowser
from PIL import Image, ImageTk
from io import BytesIO

# Local imports
from detector import perform_scan
from scheduler import ScheduleManager
from tray_manager import TrayManager
from autostart import AutoStartManager
from notification import NotificationManager
from assets.icons import get_app_icon_data, get_help_icon_data, get_settings_icon_data, get_scan_icon_data

logger = logging.getLogger(__name__)

class MainApplication(ttk.Frame):
    """Main application window for Viros Mitm."""
    
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        
        # Initialize managers
        self.schedule_manager = ScheduleManager(callback=self.scheduled_scan)
        self.notification_manager = NotificationManager("Viros Mitm")
        self.autostart_manager = AutoStartManager("Viros Mitm")
        
        # Set application icon
        self.set_app_icon()
        
        # Initialize interface elements
        self.create_variables()
        self.create_styles()
        self.create_widgets()
        self.create_layout()
        self.create_bindings()
        
        # Initialize system tray
        self.create_tray()
        
        # Start minimized if requested
        if os.environ.get("START_MINIMIZED") == "1":
            self.master.withdraw()
            self.show_tray_notification("Viros Mitm is running in the background",
                                       "The application will continue monitoring your network")
        
        # Start a scan on initialization
        self.scan_network()
    
    def set_app_icon(self):
        """Set the application icon from embedded resources"""
        try:
            icon_data = get_app_icon_data()
            icon_image = Image.open(BytesIO(icon_data))
            icon_photo = ImageTk.PhotoImage(icon_image)
            self.master.iconphoto(True, icon_photo)
            self.app_icon = icon_photo  # Save reference to prevent garbage collection
        except Exception as e:
            logger.error(f"Failed to set application icon: {e}")
    
    def create_variables(self):
        """Create tkinter variables"""
        self.scanning_var = tk.BooleanVar(value=False)
        self.schedule_interval_var = tk.StringVar(value="1")
        self.schedule_unit_var = tk.StringVar(value="hour")
        self.autostart_var = tk.BooleanVar(value=self.autostart_manager.is_enabled())
        self.show_info_var = tk.BooleanVar(value=True)
        self.last_scan_time_var = tk.StringVar(value="Not scanned yet")
        
        # Set initial values for schedule
        self.schedule_interval_var.trace_add("write", self.update_schedule)
        self.schedule_unit_var.trace_add("write", self.update_schedule)

    def create_styles(self):
        """Create custom styles for the application"""
        self.style = ttk.Style()
        
        # Configure ttk styles for a modern look
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0", font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("Accent.TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("Header.TLabel", font=("Segoe UI", 14, "bold"))
        self.style.configure("Subheader.TLabel", font=("Segoe UI", 12, "bold"))
        self.style.configure("StatusGood.TLabel", foreground="green")
        self.style.configure("StatusWarning.TLabel", foreground="orange")
        self.style.configure("StatusCritical.TLabel", foreground="red")
        
        # Configure notebook style
        self.style.configure("TNotebook", background="#f0f0f0", tabposition="n")
        self.style.map("TNotebook.Tab", background=[("selected", "#e0e0e0")])
        
        # Custom progress bar
        self.style.configure("Custom.Horizontal.TProgressbar", 
                             troughcolor="#f0f0f0", 
                             background="#4a6cd4")
    
    def create_widgets(self):
        """Create all widgets for the application"""
        # Main frame with border and padding
        self.mainframe = ttk.Frame(self, padding="10")
        
        # Create header
        self.header_frame = ttk.Frame(self.mainframe)
        self.title_label = ttk.Label(self.header_frame, text="Viros Mitm", style="Header.TLabel")
        self.subtitle_label = ttk.Label(self.header_frame, 
                                        text="Gelişmiş ARP Spoofing Tespit Aracı")
        
        # Create action buttons frame
        self.action_frame = ttk.Frame(self.mainframe)
        self.scan_button = ttk.Button(self.action_frame, text="Ağı Tara", 
                                      command=self.scan_network, style="Accent.TButton")
        self.progress_bar = ttk.Progressbar(self.action_frame, orient="horizontal", 
                                           length=200, mode="indeterminate",
                                           style="Custom.Horizontal.TProgressbar")
        self.last_scan_label = ttk.Label(self.action_frame, textvariable=self.last_scan_time_var)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.mainframe)
        
        # Results tab
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Sonuçlar")
        
        # Results summary frame
        self.summary_frame = ttk.LabelFrame(self.results_tab, text="Scan Summary", padding=10)
        self.gateway_label = ttk.Label(self.summary_frame, text="Default Gateway: Not detected")
        self.devices_label = ttk.Label(self.summary_frame, text="Devices Found: 0")
        self.status_label = ttk.Label(self.summary_frame, text="Status: Not scanned yet", 
                                     style="StatusGood.TLabel")
        
        # Results text area
        self.results_frame = ttk.LabelFrame(self.results_tab, text="Detailed Results", padding=10)
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, 
                                                    width=70, height=15)
        self.results_text.config(state=tk.DISABLED)
        
        # Settings tab
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Ayarlar")
        
        # Schedule frame
        self.schedule_frame = ttk.LabelFrame(self.settings_tab, text="Otomatik Tarama", padding=10)
        self.schedule_label = ttk.Label(self.schedule_frame, 
                                       text="Ağı otomatik olarak her şu zaman diliminde tara:")
        
        # Schedule controls
        self.schedule_controls_frame = ttk.Frame(self.schedule_frame)
        self.schedule_interval_entry = ttk.Spinbox(self.schedule_controls_frame, 
                                                 from_=1, to=24, width=5,
                                                 textvariable=self.schedule_interval_var)
        self.schedule_unit_combo = ttk.Combobox(self.schedule_controls_frame, 
                                               values=["minute", "hour"], 
                                               textvariable=self.schedule_unit_var,
                                               state="readonly", width=10)
        
        # Schedule status and controls
        self.schedule_status_frame = ttk.Frame(self.schedule_frame)
        self.schedule_status_label = ttk.Label(self.schedule_status_frame, 
                                            text="Status: Not scheduled")
        self.schedule_toggle_button = ttk.Button(self.schedule_status_frame, 
                                               text="Enable Scheduling", 
                                               command=self.toggle_scheduling)
        
        # Options frame
        self.options_frame = ttk.LabelFrame(self.settings_tab, text="Uygulama Ayarları", padding=10)
        
        # Auto-start option
        self.autostart_check = ttk.Checkbutton(self.options_frame, 
                                              text="Bilgisayar açıldığında otomatik başlat", 
                                              variable=self.autostart_var,
                                              command=self.toggle_autostart)
        
        # Display options
        self.display_frame = ttk.Frame(self.options_frame)
        self.show_info_check = ttk.Checkbutton(self.display_frame, 
                                              text="Sonuçlarda bilgi öğelerini göster", 
                                              variable=self.show_info_var,
                                              command=self.refresh_results)
        
        # System tray options
        self.systray_frame = ttk.Frame(self.options_frame)
        self.minimize_to_tray_button = ttk.Button(self.systray_frame, 
                                                 text="Sistem Tepsisinde Çalıştır", 
                                                 command=self.minimize_to_tray)
        
        # About tab
        self.about_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.about_tab, text="Hakkında")
        
        # About content
        self.about_frame = ttk.Frame(self.about_tab, padding=20)
        self.about_title = ttk.Label(self.about_frame, text="Viros Mitm", style="Header.TLabel")
        self.about_version = ttk.Label(self.about_frame, text="Version 1.0")
        self.about_description = ttk.Label(self.about_frame, 
                                         text="Gelişmiş ARP Spoofing Tespit Aracı", 
                                         wraplength=400)
        self.about_details = ttk.Label(self.about_frame, 
                                      text="Bu araç ağınızı ARP spoofing saldırılarına karşı izler. " +
                                           "ARP spoofing, saldırganların cihazlar arasındaki ağ trafiğini " +
                                           "yakalamak için kullandığı yaygın bir yöntemdir.",
                                      wraplength=400)
        
        # Help section
        self.help_frame = ttk.LabelFrame(self.about_tab, text="Yardım", padding=10)
        self.help_text = scrolledtext.ScrolledText(self.help_frame, wrap=tk.WORD, 
                                                 width=60, height=10)
        self.help_text.insert(tk.END, """
ARP Spoofing saldırıları, saldırganın sahte ARP mesajları göndererek kendi MAC 
adresini varsayılan ağ geçidi gibi başka bir ana bilgisayarın IP adresi ile 
ilişkilendirdiğinde gerçekleşir. Bu, o IP adresine gönderilmesi gereken trafiğin 
bunun yerine saldırgana gönderilmesine neden olur.

Viros Mitm'i kullanmak için:

1. Manuel tarama yapmak için "Ağı Tara" düğmesine tıklayın
2. Ayarlar sekmesinde otomatik taramayı yapılandırın
3. Viros Mitm'in sistem başlangıcında çalışması için "Bilgisayar açıldığında otomatik başlat" seçeneğini etkinleştirin
4. Uygulamanın arka planda çalışması için sistem tepsisine küçültün

Şüpheli bir etkinlik tespit edilirse, Viros Mitm sizi uyarmak için uyarılar ve 
bildirimler gösterecektir.
        """)
        self.help_text.config(state=tk.DISABLED)
        
        # Status bar
        self.status_bar = ttk.Frame(self.mainframe, relief=tk.SUNKEN)
        self.status_text = ttk.Label(self.status_bar, text="Ready")
    
    def create_layout(self):
        """Layout all widgets in the application"""
        # Configure main frame
        self.mainframe.pack(fill=tk.BOTH, expand=True)
        
        # Header layout
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        self.title_label.pack(side=tk.LEFT)
        self.subtitle_label.pack(side=tk.LEFT, padx=10)
        
        # Action buttons layout
        self.action_frame.pack(fill=tk.X, pady=(0, 10))
        self.scan_button.pack(side=tk.LEFT)
        self.progress_bar.pack(side=tk.LEFT, padx=10)
        self.last_scan_label.pack(side=tk.RIGHT)
        
        # Notebook layout
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Results tab layout
        self.summary_frame.pack(fill=tk.X, padx=5, pady=5)
        self.gateway_label.pack(anchor=tk.W, pady=2)
        self.devices_label.pack(anchor=tk.W, pady=2)
        self.status_label.pack(anchor=tk.W, pady=2)
        
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Settings tab layout
        self.schedule_frame.pack(fill=tk.X, padx=5, pady=5)
        self.schedule_label.pack(anchor=tk.W, pady=5)
        
        self.schedule_controls_frame.pack(fill=tk.X)
        self.schedule_interval_entry.pack(side=tk.LEFT, pady=5)
        self.schedule_unit_combo.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.schedule_status_frame.pack(fill=tk.X, pady=5)
        self.schedule_status_label.pack(side=tk.LEFT)
        self.schedule_toggle_button.pack(side=tk.RIGHT)
        
        self.options_frame.pack(fill=tk.X, padx=5, pady=5)
        self.autostart_check.pack(anchor=tk.W, pady=5)
        
        self.display_frame.pack(fill=tk.X, pady=5)
        self.show_info_check.pack(anchor=tk.W)
        
        self.systray_frame.pack(fill=tk.X, pady=5)
        self.minimize_to_tray_button.pack(side=tk.LEFT)
        
        # About tab layout
        self.about_frame.pack(fill=tk.X, padx=5, pady=5)
        self.about_title.pack(anchor=tk.W, pady=(0, 5))
        self.about_version.pack(anchor=tk.W)
        self.about_description.pack(anchor=tk.W, pady=5)
        self.about_details.pack(anchor=tk.W, pady=5)
        
        self.help_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.help_text.pack(fill=tk.BOTH, expand=True)
        
        # Status bar layout
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_text.pack(side=tk.LEFT, padx=5, pady=2)
    
    def create_bindings(self):
        """Create event bindings"""
        # Bind window close event
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
    
    def create_tray(self):
        """Create system tray icon and menu"""
        try:
            # Create a simple colored icon directly with PIL instead of using saved data
            from PIL import Image
            simple_icon = Image.new('RGB', (64, 64), color=(0, 120, 212))
            
            # Define menu items
            menu_items = [
                {"text": "Göster", "command": self.show_window},
                {"text": "Şimdi Tara", "command": self.scan_network},
                {"text": "Çıkış", "command": self.quit_app}
            ]
            
            # Create tray icon with the simple generated image
            self.tray_manager = TrayManager(
                "Viros Mitm",
                simple_icon,  # Passing the PIL image directly
                menu_items
            )
            
            # Set click handler
            self.tray_manager.set_click_handler(self.show_window)
            
        except Exception as e:
            logger.error(f"Error creating tray icon: {e}")
            # Continue without tray icon
    
    def show_window(self):
        """Show the main window from system tray"""
        self.master.deiconify()
        self.master.lift()
        self.master.focus_force()
    
    def minimize_to_tray(self):
        """Minimize the application to system tray"""
        try:
            self.master.withdraw()
            # Only show notification if we have a tray icon
            if hasattr(self, 'tray_manager') and self.tray_manager:
                self.show_tray_notification(
                    "Viros Mitm Arka Planda",
                    "Uygulama arka planda çalışmaya devam ediyor ve ağınızı izliyor"
                )
        except Exception as e:
            logger.error(f"Error minimizing to tray: {e}")
    
    def on_close(self):
        """Handle window close event"""
        if self.schedule_manager.is_active():
            result = messagebox.askyesnocancel(
                "Küçült veya Çıkış",
                "Zamanlanmış tarama aktif. Ne yapmak istersiniz:\n\n"
                "• Evet: Sistem tepsisine küçült (arka planda çalışmaya devam et)\n"
                "• Hayır: Uygulamadan tamamen çık\n"
                "• İptal: Uygulamaya geri dön"
            )
            
            if result is True:  # Yes
                self.minimize_to_tray()
                # Show notification that app will keep running in the background
                self.show_tray_notification(
                    "Viros Mitm Arka Planda Çalışıyor", 
                    "Uygulama arka planda çalışmaya devam edecek ve periyodik taramaları gerçekleştirecek."
                )
                return
            elif result is None:  # Cancel
                return
            # Otherwise (No), continue with application exit
        
        # Clean up and exit
        self.quit_app()
    
    def quit_app(self):
        """Quit the application properly"""
        # Stop scheduling
        self.schedule_manager.stop()
        
        # Remove tray icon
        if hasattr(self, 'tray_manager'):
            self.tray_manager.remove()
        
        # Destroy the window and exit
        self.master.destroy()
        sys.exit(0)
    
    def on_tab_changed(self, event):
        """Handle notebook tab change event"""
        # Could be used for tab-specific actions
        pass
    
    def scan_network(self):
        """Scan the network for ARP spoofing"""
        if self.scanning_var.get():
            # Already scanning, don't start a new scan
            return
        
        # Update UI
        self.scanning_var.set(True)
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        self.status_text.config(text="Scanning network...")
        
        # Start scan in a separate thread
        threading.Thread(target=self._perform_scan, daemon=True).start()
    
    def _perform_scan(self):
        """Perform the actual ARP scan in a separate thread"""
        try:
            # Perform scan
            result = perform_scan()
            
            # Update UI with results
            self.master.after(0, lambda: self.update_scan_results(result))
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            self.master.after(0, lambda: self.scan_error(str(e)))
    
    def update_scan_results(self, result):
        """Update UI with scan results"""
        if not result["success"]:
            self.scan_error(result.get("error", "Unknown error"))
            return
        
        # Update last scan time
        self.last_scan_time_var.set(f"Last scan: {result['timestamp']}")
        
        # Update summary
        gateway = result["gateway"]
        self.gateway_label.config(text=f"Default Gateway: {gateway['ip']} (MAC: {gateway['mac']})")
        
        arp_table = result["arp_table"]
        self.devices_label.config(text=f"Devices Found: {len(arp_table)}")
        
        # Check for suspicious entries and update status
        suspicious_entries = result["suspicious_entries"]
        critical_count = result["severity_counts"]["critical"]
        warning_count = result["severity_counts"]["warning"]
        
        if critical_count > 0:
            status_text = f"Status: ❌ Critical issues detected ({critical_count})"
            self.status_label.config(text=status_text, style="StatusCritical.TLabel")
            # Show notification
            self.show_critical_notification(
                f"ARP Spoofing Attack Detected!",
                f"Found {critical_count} critical issues that may indicate an active attack."
            )
        elif warning_count > 0:
            status_text = f"Status: ⚠️ Suspicious activity detected ({warning_count})"
            self.status_label.config(text=status_text, style="StatusWarning.TLabel")
            # Show notification
            self.notification_manager.show_notification(
                "Suspicious Network Activity",
                f"Found {warning_count} items that may need investigation."
            )
        else:
            self.status_label.config(text="Status: ✅ No suspicious activity detected", 
                                    style="StatusGood.TLabel")
        
        # Update results text
        self.display_results(result)
        
        # Reset UI
        self.scanning_var.set(False)
        self.scan_button.config(state=tk.NORMAL)
        self.progress_bar.stop()
        self.status_text.config(text="Scan completed")
    
    def scan_error(self, error_message):
        """Handle scan errors"""
        # Update UI
        self.scanning_var.set(False)
        self.scan_button.config(state=tk.NORMAL)
        self.progress_bar.stop()
        self.status_text.config(text=f"Error: {error_message}")
        
        # Show error message
        messagebox.showerror("Scan Error", f"An error occurred during the scan:\n\n{error_message}")
    
    def display_results(self, result):
        """Display scan results in the text area"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        # Display ARP table
        self.results_text.insert(tk.END, "ARP TABLE:\n", "header")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        self.results_text.insert(tk.END, f"{'IP Address':<15} {'MAC Address':<20} {'Interface':<10}\n")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        
        arp_table = result["arp_table"]
        for entry in arp_table:
            self.results_text.insert(tk.END, 
                                     f"{entry['ip']:<15} {entry['mac']:<20} {entry['interface']:<10}\n")
        
        # Display suspicious entries
        self.results_text.insert(tk.END, "\nANALYSIS RESULTS:\n", "header")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        
        suspicious_entries = result["suspicious_entries"]
        if suspicious_entries:
            displayed_entries = 0
            
            for entry in suspicious_entries:
                # Skip info entries if not showing them
                if entry.get("severity") == "info" and not self.show_info_var.get():
                    continue
                
                # Display the entry with appropriate tag for color
                severity = entry.get("severity", "info")
                self.results_text.insert(tk.END, entry["message"] + "\n", severity)
                displayed_entries += 1
            
            if displayed_entries == 0:
                self.results_text.insert(tk.END, "No issues to display with current filter settings.\n")
        else:
            self.results_text.insert(tk.END, "✅ No suspicious activity detected.\n")
        
        # Display summary
        self.results_text.insert(tk.END, "\nSUMMARY:\n", "header")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        self.results_text.insert(tk.END, f"Total devices: {len(arp_table)}\n")
        self.results_text.insert(tk.END, f"Critical issues: {result['severity_counts']['critical']}\n")
        self.results_text.insert(tk.END, f"Warnings: {result['severity_counts']['warning']}\n")
        self.results_text.insert(tk.END, f"Info items: {result['severity_counts']['info']}\n")
        
        # Configure tags for text styling
        self.results_text.tag_configure("header", font=("Segoe UI", 10, "bold"))
        self.results_text.tag_configure("critical", foreground="red")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("info", foreground="blue")
        
        self.results_text.config(state=tk.DISABLED)
    
    def refresh_results(self):
        """Refresh the results display with current filter settings"""
        # Check if we have results to display
        if hasattr(self, 'last_result'):
            self.display_results(self.last_result)
    
    def update_schedule(self, *args):
        """Update the schedule based on user input"""
        # Only update if the schedule is active
        if self.schedule_manager.is_active():
            try:
                interval = int(self.schedule_interval_var.get())
                unit = self.schedule_unit_var.get()
                self.schedule_manager.update(interval, unit)
                self.update_schedule_status()
            except ValueError:
                pass
    
    def toggle_scheduling(self):
        """Enable or disable scheduled scanning"""
        if self.schedule_manager.is_active():
            # Disable scheduling
            self.schedule_manager.stop()
            self.schedule_toggle_button.config(text="Zamanlayıcıyı Etkinleştir")
            self.show_tray_notification("Zamanlayıcı Devre Dışı", 
                                       "Otomatik ağ taraması devre dışı bırakıldı")
        else:
            # Enable scheduling
            try:
                interval = int(self.schedule_interval_var.get())
                unit = self.schedule_unit_var.get()
                
                # Confirm with user if interval is very short
                if unit == "minute" and interval < 5:
                    if not messagebox.askyesno("Kısa Zaman Aralığını Onayla", 
                                              f"Her {interval} dakikada bir tarama yapmak sistem performansını etkileyebilir. Devam etmek istiyor musunuz?"):
                        return
                
                self.schedule_manager.start(interval, unit)
                self.schedule_toggle_button.config(text="Zamanlayıcıyı Devre Dışı Bırak")
                
                # Show notification
                self.show_tray_notification("Zamanlayıcı Aktif", 
                                          f"Ağ her {interval} {unit} taranacak")
                
                # Ask if user wants to minimize to tray
                if self.master.winfo_viewable() and messagebox.askyesno("Sistem Tepsisine Küçült?", 
                                                          "Viros Mitm'i sistem tepsisinde çalışmaya devam etmesi için küçültmek ister misiniz?"):
                    self.minimize_to_tray()
            except ValueError:
                messagebox.showerror("Geçersiz Zaman Aralığı", "Lütfen zaman aralığı için geçerli bir sayı girin")
        
        self.update_schedule_status()
    
    def update_schedule_status(self):
        """Update the schedule status label"""
        if self.schedule_manager.is_active():
            next_run = self.schedule_manager.get_next_run_time()
            self.schedule_status_label.config(
                text=f"Durum: Aktif - Sonraki tarama: {next_run}"
            )
        else:
            self.schedule_status_label.config(text="Durum: Zamanlama aktif değil")
    
    def scheduled_scan(self):
        """Callback for scheduled scans"""
        # Perform the scan in the background
        threading.Thread(target=self._scheduled_scan_thread, daemon=True).start()
        
        # Update the schedule status
        self.master.after(1000, self.update_schedule_status)
    
    def _scheduled_scan_thread(self):
        """Run scheduled scan in a separate thread"""
        logger.info("Running scheduled scan")
        
        try:
            # Run the scan
            result = perform_scan()
            
            # Check if we need to show a notification
            if result["success"]:
                critical_count = result["severity_counts"]["critical"]
                warning_count = result["severity_counts"]["warning"]
                
                if critical_count > 0:
                    # Critical issue - show notification
                    self.show_critical_notification(
                        "ARP Spoofing Saldırısı Tespit Edildi!",
                        f"{critical_count} adet kritik sorun tespit edildi. Bu aktif bir saldırı olabileceğini gösteriyor."
                    )
                elif warning_count > 0:
                    # Warning - show notification
                    self.notification_manager.show_notification(
                        "Şüpheli Ağ Etkinliği",
                        f"{warning_count} adet inceleme gerektiren şüpheli durum tespit edildi."
                    )
            
            # Save the result for display if the window is visible
            self.last_result = result
            
            # Update UI if the window is visible
            if self.master.winfo_viewable():
                self.master.after(0, lambda: self.update_scan_results(result))
        
        except Exception as e:
            logger.error(f"Error during scheduled scan: {e}")
            # Only show error in UI if window is visible
            if self.master.winfo_viewable():
                self.master.after(0, lambda: self.scan_error(str(e)))
    
    def toggle_autostart(self):
        """Toggle automatic startup with system"""
        if self.autostart_var.get():
            # Enable autostart
            success = self.autostart_manager.enable()
            if not success:
                messagebox.showerror("Error", "Failed to set application to start with Windows")
                self.autostart_var.set(False)
            else:
                messagebox.showinfo("Autostart Enabled", 
                                   "Viros Mitm will now start automatically with Windows")
        else:
            # Disable autostart
            success = self.autostart_manager.disable()
            if not success:
                messagebox.showerror("Error", "Failed to remove application from Windows startup")
                self.autostart_var.set(True)
    
    def show_tray_notification(self, title, message):
        """Show a notification from the system tray"""
        try:
            if hasattr(self, 'notification_manager') and self.notification_manager:
                self.notification_manager.show_notification(title, message)
        except Exception as e:
            logger.error(f"Error showing notification: {e}")
    
    def show_critical_notification(self, title, message):
        """Show a critical notification with alert sound"""
        try:
            if hasattr(self, 'notification_manager') and self.notification_manager:
                self.notification_manager.show_critical_notification(title, message)
        except Exception as e:
            logger.error(f"Error showing critical notification: {e}")
