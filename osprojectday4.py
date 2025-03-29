import psutil
import platform
import time
import tkinter as tk
from tkinter import ttk, messagebox

class ProcessMonitorDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("Real-Time Process Monitor")
        self.root.geometry("1200x800")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=25)
        self.style.configure("Treeview.Heading", font=('Helvetica', 10, 'bold'))
        
        # Create main frames
        self.create_resource_panel()
        self.create_process_table()
        self.create_control_panel()
        
        # Start auto-update
        self.update_data()
    
    def create_resource_panel(self):
        """Create the top panel showing system resources"""
        resource_frame = ttk.LabelFrame(self.root, text="System Resources", padding=10)
        resource_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # CPU Usage
        self.cpu_frame = ttk.Frame(resource_frame)
        self.cpu_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.cpu_frame, text="CPU Usage:").pack(side=tk.LEFT)
        self.cpu_bars = []
        self.cpu_labels = []
        
        # Memory Usage
        self.mem_frame = ttk.Frame(resource_frame)
        self.mem_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.mem_frame, text="Memory:").pack(side=tk.LEFT)
        self.mem_bar = ttk.Progressbar(self.mem_frame, length=300)
        self.mem_bar.pack(side=tk.LEFT, padx=5)
        self.mem_label = ttk.Label(self.mem_frame, text="0% (0.0/0.0 GB)")
        self.mem_label.pack(side=tk.LEFT)
        
        # Disk Usage
        self.disk_frame = ttk.Frame(resource_frame)
        self.disk_frame.pack(fill=tk.X, pady=5)
        ttk.Label(self.disk_frame, text="Disk (C:):").pack(side=tk.LEFT)
        self.disk_bar = ttk.Progressbar(self.disk_frame, length=300)
        self.disk_bar.pack(side=tk.LEFT, padx=5)
        self.disk_label = ttk.Label(self.disk_frame, text="0% (0.0/0.0 GB)")
        self.disk_label.pack(side=tk.LEFT)
    
    def create_process_table(self):
        """Create the main process table"""
        table_frame = ttk.LabelFrame(self.root, text="Running Processes", padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create Treeview with scrollbars
        self.tree = ttk.Treeview(table_frame, columns=(
            "pid", "name", "user", "status", "cpu", "memory", "threads", "create_time"
        ), show="headings")
        
        # Configure columns
        columns = [
            ("pid", "PID", 70),
            ("name", "Name", 200),
            ("user", "User", 120),
            ("status", "Status", 100),
            ("cpu", "CPU %", 80),
            ("memory", "Memory %", 90),
            ("threads", "Threads", 70),
            ("create_time", "Start Time", 150)
        ]
        
        for col_id, heading, width in columns:
            self.tree.heading(col_id, text=heading)
            self.tree.column(col_id, width=width, anchor=tk.CENTER if col_id in ["pid", "cpu", "memory", "threads"] else tk.W)
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        x_scroll = ttk.Scrollbar(table_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        
        # Grid layout
        self.tree.grid(row=0, column=0, sticky=tk.NSEW)
        y_scroll.grid(row=0, column=1, sticky=tk.NS)
        x_scroll.grid(row=1, column=0, sticky=tk.EW)
        
        # Configure grid weights
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        
        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Kill Process", command=self.kill_selected_process)
        self.context_menu.add_command(label="Show Details", command=self.show_process_details)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def create_control_panel(self):
        """Create the bottom control panel"""
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Refresh controls
        ttk.Label(control_frame, text="Refresh:").pack(side=tk.LEFT)
        self.refresh_var = tk.IntVar(value=2)
        ttk.Radiobutton(control_frame, text="1s", variable=self.refresh_var, value=1).pack(side=tk.LEFT)
        ttk.Radiobutton(control_frame, text="2s", variable=self.refresh_var, value=2).pack(side=tk.LEFT)
        ttk.Radiobutton(control_frame, text="5s", variable=self.refresh_var, value=5).pack(side=tk.LEFT)
        
        # Process filter
        ttk.Label(control_frame, text="Filter:").pack(side=tk.LEFT, padx=(20, 5))
        self.filter_var = tk.StringVar()
        self.filter_entry = ttk.Entry(control_frame, textvariable=self.filter_var, width=30)
        self.filter_entry.pack(side=tk.LEFT)
        self.filter_entry.bind("<Return>", lambda e: self.update_data())
        
        # Buttons
        ttk.Button(control_frame, text="Kill Process", command=self.kill_selected_process).pack(side=tk.RIGHT, padx=5)
        ttk.Button(control_frame, text="Refresh Now", command=self.update_data).pack(side=tk.RIGHT)
    
    def update_data(self):
        """Update all dashboard data"""
        try:
            # Update CPU usage
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            avg_cpu = sum(cpu_percent)/len(cpu_percent)
            
            # Clear existing CPU bars if count doesn't match
            if len(self.cpu_bars) != len(cpu_percent):
                for widget in self.cpu_frame.winfo_children()[1:]:
                    widget.destroy()
                self.cpu_bars = []
                self.cpu_labels = []
                
                for i, usage in enumerate(cpu_percent):
                    ttk.Label(self.cpu_frame, text=f"Core {i}:").pack(side=tk.LEFT)
                    bar = ttk.Progressbar(self.cpu_frame, length=100)
                    bar.pack(side=tk.LEFT, padx=2)
                    label = ttk.Label(self.cpu_frame, text="0%", width=5)
                    label.pack(side=tk.LEFT)
                    self.cpu_bars.append(bar)
                    self.cpu_labels.append(label)
            
            # Update CPU bars
            for i, (bar, label, usage) in enumerate(zip(self.cpu_bars, self.cpu_labels, cpu_percent)):
                bar['value'] = usage
                label.config(text=f"{usage:.1f}%")
                bar['style'] = 'red.Horizontal.TProgressbar' if usage > 90 else \
                              'yellow.Horizontal.TProgressbar' if usage > 70 else \
                              'green.Horizontal.TProgressbar'
            
            # Update memory usage
            mem = psutil.virtual_memory()
            self.mem_bar['value'] = mem.percent
            self.mem_label.config(text=f"{mem.percent:.1f}% ({mem.used/1024**3:.1f}/{mem.total/1024**3:.1f} GB)")
            self.mem_bar['style'] = 'red.Horizontal.TProgressbar' if mem.percent > 90 else \
                                   'yellow.Horizontal.TProgressbar' if mem.percent > 70 else \
                                   'green.Horizontal.TProgressbar'
            
            # Update disk usage
            disk = psutil.disk_usage('/')
            self.disk_bar['value'] = disk.percent
            self.disk_label.config(text=f"{disk.percent:.1f}% ({disk.used/1024**3:.1f}/{disk.total/1024**3:.1f} GB)")
            self.disk_bar['style'] = 'red.Horizontal.TProgressbar' if disk.percent > 90 else \
                                    'yellow.Horizontal.TProgressbar' if disk.percent > 70 else \
                                    'green.Horizontal.TProgressbar'
            
            # Update process list
            self.update_process_table()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update data: {str(e)}")
        
        # Schedule next update
        self.root.after(self.refresh_var.get() * 1000, self.update_data)
    
    def update_process_table(self):
        """Update the process table with current process data"""
        filter_text = self.filter_var.get().lower()
        
        # Clear existing items (but preserve sort order)
        sort_column = self.tree.heading('pid')['text'].lower().replace(' %', '').replace(' ', '_')
        sort_direction = self.tree.heading(sort_column)['image']
        self.tree.delete(*self.tree.get_children())
        
        # Get and display processes
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'num_threads', 'create_time']):
            try:
                p_info = proc.info
                
                # Apply filter
                if filter_text and filter_text not in p_info['name'].lower() and \
                   filter_text not in str(p_info['pid']) and \
                   filter_text not in p_info['username'].lower():
                    continue
                
                # Format create time
                create_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p_info['create_time']))
                
                # Insert into treeview
                self.tree.insert("", "end", values=(
                    p_info['pid'],
                    p_info['name'],
                    p_info['username'],
                    p_info['status'],
                    f"{p_info['cpu_percent']:.1f}",
                    f"{p_info['memory_percent']:.1f}",
                    p_info['num_threads'],
                    create_time
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Reapply sort if needed
        if sort_direction:
            self.tree.heading(sort_column, command=lambda: self.sort_treeview(sort_column, not sort_direction.endswith('up')))
            self.sort_treeview(sort_column, sort_direction.endswith('up'))
    
    def sort_treeview(self, column, reverse):
        """Sort treeview by column"""
        items = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        
        # Try to convert to number if possible
        try:
            items.sort(key=lambda x: float(x[0]), reverse=reverse)
        except ValueError:
            items.sort(reverse=reverse)
        
        # Rearrange items
        for index, (val, item) in enumerate(items):
            self.tree.move(item, '', index)
        
        # Update sort indicator
        for col in self.tree['columns']:
            self.tree.heading(col, image='')
        
        # Set new sort indicator
        sort_icon = "▲" if reverse else "▼"
        self.tree.heading(column, image=sort_icon)
    
    def show_context_menu(self, event):
        """Show context menu for process actions"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)
    
    def kill_selected_process(self):
        """Kill the selected process"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No process selected")
            return
        
        pid = int(self.tree.item(selected[0], 'values')[0])
        name = self.tree.item(selected[0], 'values')[1]
        
        if messagebox.askyesno("Confirm", f"Kill process {pid} ({name})?"):
            try:
                p = psutil.Process(pid)
                p.terminate()
                messagebox.showinfo("Success", f"Process {pid} terminated")
                self.update_data()
            except psutil.NoSuchProcess:
                messagebox.showerror("Error", f"Process {pid} not found")
            except psutil.AccessDenied:
                messagebox.showerror("Error", f"Permission denied to kill process {pid}")
    
    def show_process_details(self):
        """Show detailed information about selected process"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No process selected")
            return
        
        pid = int(self.tree.item(selected[0], 'values')[0])
        
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                info = {
                    "PID": pid,
                    "Name": p.name(),
                    "Status": p.status(),
                    "User": p.username(),
                    "CPU %": f"{p.cpu_percent():.1f}",
                    "Memory %": f"{p.memory_percent():.1f}",
                    "Threads": p.num_threads(),
                    "Create Time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(p.create_time())),
                    "Executable": p.exe(),
                    "Working Dir": p.cwd(),
                    "Command Line": " ".join(p.cmdline()),
                    "Parent PID": p.ppid(),
                    "Children": len(p.children()),
                    "Open Files": len(p.open_files()),
                    "Connections": len(p.connections())
                }
                
                details = "\n".join(f"{k}: {v}" for k, v in info.items())
                messagebox.showinfo(f"Process Details - PID {pid}", details)
        except psutil.NoSuchProcess:
            messagebox.showerror("Error", f"Process {pid} not found")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get process details: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    
    # Configure styles
    style = ttk.Style()
    style.theme_use('clam')
    
    # Custom progress bar styles
    style.configure("green.Horizontal.TProgressbar", troughcolor='#f0f0f0', background='#4CAF50')
    style.configure("yellow.Horizontal.TProgressbar", troughcolor='#f0f0f0', background='#FFC107')
    style.configure("red.Horizontal.TProgressbar", troughcolor='#f0f0f0', background='#F44336')
    
    app = ProcessMonitorDashboard(root)
    root.mainloop()
