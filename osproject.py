import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import psutil
import time
import threading
import json
import os
from datetime import datetime

class ProcessManagementInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Process Management Interface")
        self.root.geometry("1200x800")
        
        # Alert thresholds
        self.thresholds = {
            'cpu': 80,
            'memory': 80,
            'process_count': 200,
            'zombie_processes': 1
        }
        
        # Automation rules
        self.rules = []
        
        # Load saved settings if they exist
        self.load_settings()
        
        # Create tabs
        self.tab_control = ttk.Notebook(root)
        
        # Process Control Tab
        self.tab_process = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_process, text='Process Control')
        
        # Alert System Tab
        self.tab_alerts = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_alerts, text='Alert System')
        
        # Automation Rules Tab
        self.tab_rules = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_rules, text='Automation Rules')
        
        # Reporting Tab
        self.tab_reports = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_reports, text='Reporting & Logging')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Initialize all tabs
        self.init_process_control_tab()
        self.init_alert_system_tab()
        self.init_automation_rules_tab()
        self.init_reporting_tab()
        
        # Start the process monitor thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_processes)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def init_process_control_tab(self):
        # Process list frame
        process_frame = ttk.LabelFrame(self.tab_process, text="Running Processes")
        process_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Treeview for processes
        columns = ("pid", "name", "status", "cpu", "memory", "user")
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show="headings")
        
        for col in columns:
            self.process_tree.heading(col, text=col.capitalize())
            self.process_tree.column(col, width=100)
        
        self.process_tree.column("name", width=200)
        self.process_tree.column("user", width=150)
        
        self.process_tree.pack(fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        # Control buttons frame
        control_frame = ttk.Frame(self.tab_process)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Control buttons
        ttk.Button(control_frame, text="Refresh", command=self.refresh_process_list).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Kill Process", command=self.kill_process).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Terminate Process", command=self.terminate_process).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Change Priority", command=self.change_priority).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Pause/Resume", command=self.pause_resume_process).pack(side="left", padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(self.tab_process, textvariable=self.status_var).pack(side="bottom", fill="x", padx=10, pady=5)
    
    def init_alert_system_tab(self):
        # Threshold settings frame
        threshold_frame = ttk.LabelFrame(self.tab_alerts, text="Alert Thresholds")
        threshold_frame.pack(fill="x", padx=10, pady=10)
        
        # CPU threshold
        ttk.Label(threshold_frame, text="CPU Usage (%):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.cpu_threshold = tk.IntVar(value=self.thresholds['cpu'])
        ttk.Entry(threshold_frame, textvariable=self.cpu_threshold, width=5).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Memory threshold
        ttk.Label(threshold_frame, text="Memory Usage (%):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.memory_threshold = tk.IntVar(value=self.thresholds['memory'])
        ttk.Entry(threshold_frame, textvariable=self.memory_threshold, width=5).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Process count threshold
        ttk.Label(threshold_frame, text="Process Count:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.process_count_threshold = tk.IntVar(value=self.thresholds['process_count'])
        ttk.Entry(threshold_frame, textvariable=self.process_count_threshold, width=5).grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Zombie process threshold
        ttk.Label(threshold_frame, text="Zombie Processes:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.zombie_threshold = tk.IntVar(value=self.thresholds['zombie_processes'])
        ttk.Entry(threshold_frame, textvariable=self.zombie_threshold, width=5).grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        # Save thresholds button
        ttk.Button(threshold_frame, text="Save Thresholds", command=self.save_thresholds).grid(row=4, column=0, columnspan=2, pady=10)
        
        # Alert log frame
        log_frame = ttk.LabelFrame(self.tab_alerts, text="Alert Log")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.alert_log = tk.Text(log_frame, wrap="word", state="disabled")
        self.alert_log.pack(fill="both", expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.alert_log.yview)
        scrollbar.pack(side="right", fill="y")
        self.alert_log.configure(yscrollcommand=scrollbar.set)
        
        # Clear log button
        ttk.Button(log_frame, text="Clear Log", command=self.clear_alert_log).pack(side="bottom", pady=5)
    
    def init_automation_rules_tab(self):
        # Rules list frame
        rules_frame = ttk.LabelFrame(self.tab_rules, text="Automation Rules")
        rules_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Treeview for rules
        columns = ("id", "condition", "action", "target", "active")
        self.rules_tree = ttk.Treeview(rules_frame, columns=columns, show="headings")
        
        for col in columns:
            self.rules_tree.heading(col, text=col.capitalize())
            self.rules_tree.column(col, width=100)
        
        self.rules_tree.column("condition", width=200)
        self.rules_tree.column("action", width=150)
        
        self.rules_tree.pack(fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(rules_frame, orient="vertical", command=self.rules_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        # Control buttons frame
        control_frame = ttk.Frame(self.tab_rules)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Control buttons
        ttk.Button(control_frame, text="Add Rule", command=self.add_rule).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Edit Rule", command=self.edit_rule).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Delete Rule", command=self.delete_rule).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Toggle Active", command=self.toggle_rule_active).pack(side="left", padx=5)
        
        # Status bar
        self.rules_status_var = tk.StringVar()
        self.rules_status_var.set("Ready")
        ttk.Label(self.tab_rules, textvariable=self.rules_status_var).pack(side="bottom", fill="x", padx=10, pady=5)
    
    def init_reporting_tab(self):
        # Report generation frame
        report_frame = ttk.LabelFrame(self.tab_reports, text="Generate Reports")
        report_frame.pack(fill="x", padx=10, pady=10)
        
        # Report options
        ttk.Button(report_frame, text="Resource Usage Report", command=self.generate_resource_report).pack(side="left", padx=5, pady=5)
        ttk.Button(report_frame, text="Process List Report", command=self.generate_process_report).pack(side="left", padx=5, pady=5)
        ttk.Button(report_frame, text="System Event Log", command=self.generate_event_log).pack(side="left", padx=5, pady=5)
        
        # Report display frame
        display_frame = ttk.LabelFrame(self.tab_reports, text="Report Output")
        display_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.report_text = tk.Text(display_frame, wrap="word", state="disabled")
        self.report_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(display_frame, orient="vertical", command=self.report_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.report_text.configure(yscrollcommand=scrollbar.set)
        
        # Export buttons
        export_frame = ttk.Frame(display_frame)
        export_frame.pack(side="bottom", fill="x", pady=5)
        
        ttk.Button(export_frame, text="Save to File", command=self.save_report_to_file).pack(side="left", padx=5)
        ttk.Button(export_frame, text="Clear Output", command=self.clear_report_output).pack(side="left", padx=5)
    
    def refresh_process_list(self):
        self.process_tree.delete(*self.process_tree.get_children())
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'username']):
            try:
                self.process_tree.insert("", "end", values=(
                    proc.info['pid'],
                    proc.info['name'],
                    proc.info['status'],
                    f"{proc.info['cpu_percent']:.1f}",
                    f"{proc.info['memory_percent']:.1f}",
                    proc.info['username']
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.status_var.set(f"Process list refreshed at {datetime.now().strftime('%H:%M:%S')}")
    
    def kill_process(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process first")
            return
        
        pid = int(self.process_tree.item(selected[0])['values'][0])
        name = self.process_tree.item(selected[0])['values'][1]
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to kill process {name} (PID: {pid})?"):
            try:
                p = psutil.Process(pid)
                p.kill()
                self.log_alert(f"Killed process {name} (PID: {pid})", "ACTION")
                self.refresh_process_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to kill process: {e}")
    
    def terminate_process(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process first")
            return
        
        pid = int(self.process_tree.item(selected[0])['values'][0])
        name = self.process_tree.item(selected[0])['values'][1]
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to terminate process {name} (PID: {pid})?"):
            try:
                p = psutil.Process(pid)
                p.terminate()
                self.log_alert(f"Terminated process {name} (PID: {pid})", "ACTION")
                self.refresh_process_list()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to terminate process: {e}")
    
    def change_priority(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process first")
            return
        
        pid = int(self.process_tree.item(selected[0])['values'][0])
        name = self.process_tree.item(selected[0])['values'][1]
        
        try:
            p = psutil.Process(pid)
            current_nice = p.nice()
            
            new_nice = simpledialog.askinteger(
                "Change Priority",
                f"Enter new nice value for {name} (PID: {pid})\nCurrent: {current_nice}",
                minvalue=-20,
                maxvalue=19
            )
            
            if new_nice is not None:
                p.nice(new_nice)
                self.log_alert(f"Changed priority of {name} (PID: {pid}) from {current_nice} to {new_nice}", "ACTION")
                self.refresh_process_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change priority: {e}")
    
    def pause_resume_process(self):
        selected = self.process_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a process first")
            return
        
        pid = int(self.process_tree.item(selected[0])['values'][0])
        name = self.process_tree.item(selected[0])['values'][1]
        status = self.process_tree.item(selected[0])['values'][2]
        
        try:
            p = psutil.Process(pid)
            if status == 'stopped':
                p.resume()
                action = "resumed"
            else:
                p.suspend()
                action = "paused"
            
            self.log_alert(f"{action.capitalize()} process {name} (PID: {pid})", "ACTION")
            self.refresh_process_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to pause/resume process: {e}")
    
    def save_thresholds(self):
        self.thresholds = {
            'cpu': self.cpu_threshold.get(),
            'memory': self.memory_threshold.get(),
            'process_count': self.process_count_threshold.get(),
            'zombie_processes': self.zombie_threshold.get()
        }
        self.save_settings()
        messagebox.showinfo("Success", "Threshold settings saved")
    
    def log_alert(self, message, alert_type="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{alert_type}] {message}\n"
        
        self.alert_log.config(state="normal")
        self.alert_log.insert("end", log_entry)
        self.alert_log.config(state="disabled")
        self.alert_log.see("end")
        
        # Flash window for important alerts
        if alert_type in ("WARNING", "ERROR"):
            self.root.attributes("-topmost", True)
            self.root.after(100, lambda: self.root.attributes("-topmost", False))
    
    def clear_alert_log(self):
        self.alert_log.config(state="normal")
        self.alert_log.delete("1.0", "end")
        self.alert_log.config(state="disabled")
    
    def add_rule(self):
        # Simplified rule creation - in a real app this would be more sophisticated
        rule_dialog = tk.Toplevel(self.root)
        rule_dialog.title("Add New Rule")
        rule_dialog.geometry("400x300")
        
        ttk.Label(rule_dialog, text="Condition:").pack(pady=5)
        condition_var = tk.StringVar()
        condition_combo = ttk.Combobox(rule_dialog, textvariable=condition_var, 
                                      values=["Process CPU > threshold", "Process memory > threshold", 
                                             "Process dies", "Zombie process detected"])
        condition_combo.pack(pady=5)
        
        ttk.Label(rule_dialog, text="Action:").pack(pady=5)
        action_var = tk.StringVar()
        action_combo = ttk.Combobox(rule_dialog, textvariable=action_var, 
                                   values=["Kill process", "Restart process", "Notify admin", "Log event"])
        action_combo.pack(pady=5)
        
        ttk.Label(rule_dialog, text="Target Process (if applicable):").pack(pady=5)
        target_var = tk.StringVar()
        ttk.Entry(rule_dialog, textvariable=target_var).pack(pady=5)
        
        ttk.Label(rule_dialog, text="Threshold (if applicable):").pack(pady=5)
        threshold_var = tk.StringVar()
        ttk.Entry(rule_dialog, textvariable=threshold_var).pack(pady=5)
        
        active_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(rule_dialog, text="Active", variable=active_var).pack(pady=5)
        
        def save_rule():
            rule_id = len(self.rules) + 1
            self.rules.append({
                'id': rule_id,
                'condition': condition_var.get(),
                'action': action_var.get(),
                'target': target_var.get(),
                'threshold': threshold_var.get(),
                'active': active_var.get()
            })
            self.update_rules_tree()
            rule_dialog.destroy()
            self.save_settings()
        
        ttk.Button(rule_dialog, text="Save Rule", command=save_rule).pack(pady=10)
    
    def edit_rule(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule first")
            return
        
        # Similar to add_rule but with existing values
        # Implementation omitted for brevity
        pass
    
    def delete_rule(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule first")
            return
        
        rule_id = int(self.rules_tree.item(selected[0])['values'][0])
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this rule?"):
            self.rules = [rule for rule in self.rules if rule['id'] != rule_id]
            self.update_rules_tree()
            self.save_settings()
    
    def toggle_rule_active(self):
        selected = self.rules_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a rule first")
            return
        
        rule_id = int(self.rules_tree.item(selected[0])['values'][0])
        for rule in self.rules:
            if rule['id'] == rule_id:
                rule['active'] = not rule['active']
                break
        
        self.update_rules_tree()
        self.save_settings()
    
    def update_rules_tree(self):
        self.rules_tree.delete(*self.rules_tree.get_children())
        for rule in self.rules:
            self.rules_tree.insert("", "end", values=(
                rule['id'],
                rule['condition'],
                rule['action'],
                rule['target'],
                "Yes" if rule['active'] else "No"
            ))
    
    def generate_resource_report(self):
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        report = f"=== System Resource Report ===\n"
        report += f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report += f"CPU Usage: {cpu_percent}%\n"
        report += f"Memory Usage: {memory.percent}% ({memory.used/1024/1024:.1f} MB used of {memory.total/1024/1024:.1f} MB)\n"
        report += f"Disk Usage: {disk.percent}% ({disk.used/1024/1024:.1f} MB used of {disk.total/1024/1024:.1f} MB)\n"
        
        self.display_report(report)
    
    def generate_process_report(self):
        report = f"=== Process List Report ===\n"
        report += f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        report += f"{'PID':>6} {'Name':<20} {'Status':<10} {'CPU%':>6} {'Memory%':>8} {'User':<15}\n"
        report += "-" * 70 + "\n"
        
        for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent', 'username']):
            try:
                report += f"{proc.info['pid']:>6} {proc.info['name'][:20]:<20} {proc.info['status']:<10} " \
                         f"{proc.info['cpu_percent']:>6.1f} {proc.info['memory_percent']:>8.1f} " \
                         f"{proc.info['username'][:15] if proc.info['username'] else 'N/A':<15}\n"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.display_report(report)
    
    def generate_event_log(self):
        self.display_report("Event log functionality would display system events here")
    
    def display_report(self, content):
        self.report_text.config(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.insert("1.0", content)
        self.report_text.config(state="disabled")
    
    def save_report_to_file(self):
        content = self.report_text.get("1.0", "end-1c")
        if not content.strip():
            messagebox.showwarning("Warning", "No report content to save")
            return
        
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        try:
            with open(filename, 'w') as f:
                f.write(content)
            messagebox.showinfo("Success", f"Report saved to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save report: {e}")
    
    def clear_report_output(self):
        self.report_text.config(state="normal")
        self.report_text.delete("1.0", "end")
        self.report_text.config(state="disabled")
    
    def monitor_processes(self):
        while self.running:
            try:
                # Check CPU threshold
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.thresholds['cpu']:
                    self.log_alert(f"CPU usage exceeded threshold: {cpu_percent}% > {self.thresholds['cpu']}%", "WARNING")
                
                # Check memory threshold
                memory = psutil.virtual_memory()
                if memory.percent > self.thresholds['memory']:
                    self.log_alert(f"Memory usage exceeded threshold: {memory.percent}% > {self.thresholds['memory']}%", "WARNING")
                
                # Check process count
                process_count = len(list(psutil.process_iter()))
                if process_count > self.thresholds['process_count']:
                    self.log_alert(f"Process count exceeded threshold: {process_count} > {self.thresholds['process_count']}", "WARNING")
                
                # Check for zombie processes
                zombies = []
                for proc in psutil.process_iter(['status']):
                    try:
                        if proc.info['status'] == psutil.STATUS_ZOMBIE:
                            zombies.append(proc.pid)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                if len(zombies) >= self.thresholds['zombie_processes']:
                    self.log_alert(f"Zombie processes detected: {len(zombies)} (PIDs: {', '.join(map(str, zombies))})", "WARNING")
                
                # Check automation rules
                self.check_automation_rules()
                
            except Exception as e:
                self.log_alert(f"Monitoring error: {str(e)}", "ERROR")
            
            time.sleep(5)
    
    def check_automation_rules(self):
        for rule in self.rules:
            if not rule['active']:
                continue
            
            try:
                if rule['condition'] == "Process CPU > threshold":
                    threshold = float(rule['threshold']) if rule['threshold'] else 80
                    target = rule['target']
                    
                    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                        try:
                            if proc.info['name'] == target and proc.info['cpu_percent'] > threshold:
                                self.execute_rule_action(rule, proc)
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue
                
                # Other rule conditions would be implemented similarly
                
            except Exception as e:
                self.log_alert(f"Rule execution error: {str(e)}", "ERROR")
    
    def execute_rule_action(self, rule, proc=None):
        if rule['action'] == "Kill process":
            try:
                p = psutil.Process(proc.info['pid'])
                p.kill()
                self.log_alert(f"Rule executed: Killed process {proc.info['name']} (PID: {proc.info['pid']}) due to {rule['condition']}", "ACTION")
            except Exception as e:
                self.log_alert(f"Failed to execute rule: {str(e)}", "ERROR")
        
        # Other actions would be implemented similarly
    
    def save_settings(self):
        settings = {
            'thresholds': self.thresholds,
            'rules': self.rules
        }
        
        try:
            with open('process_manager_settings.json', 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            self.log_alert(f"Failed to save settings: {str(e)}", "ERROR")
    
    def load_settings(self):
        if os.path.exists('process_manager_settings.json'):
            try:
                with open('process_manager_settings.json', 'r') as f:
                    settings = json.load(f)
                
                self.thresholds = settings.get('thresholds', self.thresholds)
                self.rules = settings.get('rules', [])
                
                # Update UI variables
                self.cpu_threshold.set(self.thresholds['cpu'])
                self.memory_threshold.set(self.thresholds['memory'])
                self.process_count_threshold.set(self.thresholds['process_count'])
                self.zombie_threshold.set(self.thresholds['zombie_processes'])
                
            except Exception as e:
                self.log_alert(f"Failed to load settings: {str(e)}", "ERROR")
    
    def on_closing(self):
        self.running = False
        self.save_settings()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessManagementInterface(root)
    root.mainloop()
