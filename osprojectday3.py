import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import threading
from collections import deque
import json
import os
from datetime import datetime

class SystemMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("System Resource Monitor & Process Manager")
        self.root.geometry("1400x900")
        
        # Data storage for historical metrics
        self.cpu_history = deque(maxlen=60)
        self.memory_history = deque(maxlen=60)
        self.disk_history = deque(maxlen=60)
        self.network_history = deque(maxlen=60)
        
        # Alert thresholds and rules
        self.thresholds = {
            'cpu': 80,
            'memory': 80,
            'process_count': 200,
            'zombie_processes': 1
        }
        self.rules = []
        self.load_settings()
        
        # Create tabs
        self.tab_control = ttk.Notebook(root)
        
        # System Monitor Tabs
        self.tab_cpu = ttk.Frame(self.tab_control)
        self.tab_memory = ttk.Frame(self.tab_control)
        self.tab_disk = ttk.Frame(self.tab_control)
        self.tab_network = ttk.Frame(self.tab_control)
        
        # Process Management Tabs
        self.tab_process = ttk.Frame(self.tab_control)
        self.tab_alerts = ttk.Frame(self.tab_control)
        self.tab_rules = ttk.Frame(self.tab_control)
        self.tab_reports = ttk.Frame(self.tab_control)
        
        # Add tabs to notebook
        self.tab_control.add(self.tab_cpu, text='CPU Monitor')
        self.tab_control.add(self.tab_memory, text='Memory Monitor')
        self.tab_control.add(self.tab_disk, text='Disk Monitor')
        self.tab_control.add(self.tab_network, text='Network Monitor')
        self.tab_control.add(self.tab_process, text='Process Control')
        self.tab_control.add(self.tab_alerts, text='Alert System')
        self.tab_control.add(self.tab_rules, text='Automation Rules')
        self.tab_control.add(self.tab_reports, text='Reporting')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Initialize all tabs
        self.init_cpu_tab()
        self.init_memory_tab()
        self.init_disk_tab()
        self.init_network_tab()
        self.init_process_control_tab()
        self.init_alert_system_tab()
        self.init_automation_rules_tab()
        self.init_reporting_tab()
        
        # Start monitoring threads
        self.running = True
        self.monitor_thread = threading.Thread(target=self.update_metrics)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        self.process_monitor_thread = threading.Thread(target=self.monitor_processes)
        self.process_monitor_thread.daemon = True
        self.process_monitor_thread.start()
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ====================== SYSTEM MONITOR FUNCTIONS ======================
    def init_cpu_tab(self):
        cpu_frame = ttk.LabelFrame(self.tab_cpu, text="CPU Usage")
        cpu_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Per-core CPU usage
        core_frame = ttk.Frame(cpu_frame)
        core_frame.pack(fill="x", padx=5, pady=5)
        
        self.core_bars = []
        cores = psutil.cpu_count(logical=True)
        
        for i in range(cores):
            frame = ttk.Frame(core_frame)
            frame.pack(fill="x", padx=5, pady=2)
            ttk.Label(frame, text=f"Core {i}:").pack(side="left")
            canvas = tk.Canvas(frame, height=20, bg='white')
            canvas.pack(fill="x", expand=True)
            self.core_bars.append(canvas)
        
        # CPU Usage Graph
        self.cpu_fig, self.cpu_ax = plt.subplots(figsize=(8, 3))
        self.cpu_ax.set_title("CPU Usage History")
        self.cpu_ax.set_xlabel("Time (seconds)")
        self.cpu_ax.set_ylabel("Usage %")
        self.cpu_ax.set_ylim(0, 100)
        self.cpu_line, = self.cpu_ax.plot([], [], 'b-')
        
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_fig, master=cpu_frame)
        self.cpu_canvas.draw()
        self.cpu_canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Top Processes Frame
        top_process_frame = ttk.LabelFrame(cpu_frame, text="Top CPU Processes")
        top_process_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("pid", "name", "cpu_percent", "user")
        self.top_cpu_tree = ttk.Treeview(top_process_frame, columns=columns, show="headings")
        
        for col in columns:
            self.top_cpu_tree.heading(col, text=col.capitalize())
            self.top_cpu_tree.column(col, width=100)
        
        self.top_cpu_tree.column("name", width=200)
        self.top_cpu_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(top_process_frame, orient="vertical", command=self.top_cpu_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.top_cpu_tree.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(cpu_frame, text="Refresh", command=self.update_top_cpu_processes).pack(side="bottom", pady=5)

    def init_memory_tab(self):
        mem_frame = ttk.LabelFrame(self.tab_memory, text="Memory Usage")
        mem_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Memory Bar
        mem_bar_frame = ttk.Frame(mem_frame)
        mem_bar_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(mem_bar_frame, text="RAM:").pack(side="left")
        self.mem_canvas = tk.Canvas(mem_bar_frame, height=30, bg='white')
        self.mem_canvas.pack(fill="x", expand=True)
        
        # Memory Pie Chart
        self.mem_fig, self.mem_ax = plt.subplots(figsize=(5, 3))
        self.mem_ax.set_title("Memory Distribution")
        self.mem_pie = self.mem_ax.pie([1, 1, 1, 1], labels=['Used', 'Buffers', 'Cached', 'Free'], 
                                      autopct='%1.1f%%', startangle=90)
        
        self.mem_canvas_pie = FigureCanvasTkAgg(self.mem_fig, master=mem_frame)
        self.mem_canvas_pie.draw()
        self.mem_canvas_pie.get_tk_widget().pack(fill="both", expand=True)
        
        # Swap Memory
        swap_frame = ttk.Frame(mem_frame)
        swap_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(swap_frame, text="Swap:").pack(side="left")
        self.swap_canvas = tk.Canvas(swap_frame, height=20, bg='white')
        self.swap_canvas.pack(fill="x", expand=True)
        
        # Top Processes Frame
        top_process_frame = ttk.LabelFrame(mem_frame, text="Top Memory Processes")
        top_process_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("pid", "name", "memory_percent", "rss", "user")
        self.top_mem_tree = ttk.Treeview(top_process_frame, columns=columns, show="headings")
        
        for col in columns:
            self.top_mem_tree.heading(col, text=col.capitalize())
            self.top_mem_tree.column(col, width=100)
        
        self.top_mem_tree.column("name", width=200)
        self.top_mem_tree.heading("rss", text="RSS (MB)")
        self.top_mem_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(top_process_frame, orient="vertical", command=self.top_mem_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.top_mem_tree.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(mem_frame, text="Refresh", command=self.update_top_mem_processes).pack(side="bottom", pady=5)

    def init_disk_tab(self):
        disk_frame = ttk.LabelFrame(self.tab_disk, text="Disk I/O")
        disk_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Disk Usage Graph
        self.disk_fig, (self.disk_ax1, self.disk_ax2) = plt.subplots(2, 1, figsize=(8, 6))
        self.disk_ax1.set_title("Disk Read/Write Throughput")
        self.disk_ax1.set_ylabel("MB/s")
        self.disk_read_line, = self.disk_ax1.plot([], [], 'g-', label='Read')
        self.disk_write_line, = self.disk_ax1.plot([], [], 'r-', label='Write')
        self.disk_ax1.legend()
        self.disk_ax2.set_title("Disk Queue Length")
        self.disk_ax2.set_ylabel("Queue Length")
        self.disk_queue_line, = self.disk_ax2.plot([], [], 'b-')
        
        self.disk_canvas = FigureCanvasTkAgg(self.disk_fig, master=disk_frame)
        self.disk_canvas.draw()
        self.disk_canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Disk Partitions Info
        part_frame = ttk.LabelFrame(disk_frame, text="Disk Partitions")
        part_frame.pack(fill="x", padx=10, pady=5)
        
        columns = ("device", "mountpoint", "fstype", "total", "used", "free", "percent")
        self.part_tree = ttk.Treeview(part_frame, columns=columns, show="headings")
        
        for col in columns:
            self.part_tree.heading(col, text=col.capitalize())
            self.part_tree.column(col, width=100)
        
        self.part_tree.column("mountpoint", width=150)
        self.part_tree.column("fstype", width=100)
        self.part_tree.pack(fill="x")
        
        scrollbar = ttk.Scrollbar(part_frame, orient="horizontal", command=self.part_tree.xview)
        scrollbar.pack(side="bottom", fill="x")
        self.part_tree.configure(xscrollcommand=scrollbar.set)
        
        # Top Disk Processes
        top_process_frame = ttk.LabelFrame(disk_frame, text="Top Disk Processes")
        top_process_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("pid", "name", "read_bytes", "write_bytes", "user")
        self.top_disk_tree = ttk.Treeview(top_process_frame, columns=columns, show="headings")
        
        for col in columns:
            self.top_disk_tree.heading(col, text=col.capitalize())
            self.top_disk_tree.column(col, width=100)
        
        self.top_disk_tree.column("name", width=200)
        self.top_disk_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(top_process_frame, orient="vertical", command=self.top_disk_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.top_disk_tree.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(disk_frame, text="Refresh", command=self.update_disk_info).pack(side="bottom", pady=5)

    def init_network_tab(self):
        net_frame = ttk.LabelFrame(self.tab_network, text="Network Activity")
        net_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Network Graph
        self.net_fig, (self.net_ax1, self.net_ax2) = plt.subplots(2, 1, figsize=(8, 6))
        self.net_ax1.set_title("Network Throughput")
        self.net_ax1.set_ylabel("MB/s")
        self.net_sent_line, = self.net_ax1.plot([], [], 'g-', label='Sent')
        self.net_recv_line, = self.net_ax1.plot([], [], 'r-', label='Received')
        self.net_ax1.legend()
        self.net_ax2.set_title("Connection Count")
        self.net_ax2.set_ylabel("Connections")
        self.net_conn_line, = self.net_ax2.plot([], [], 'b-')
        
        self.net_canvas = FigureCanvasTkAgg(self.net_fig, master=net_frame)
        self.net_canvas.draw()
        self.net_canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Network Interfaces
        iface_frame = ttk.LabelFrame(net_frame, text="Network Interfaces")
        iface_frame.pack(fill="x", padx=10, pady=5)
        
        columns = ("name", "ip", "sent", "recv", "speed")
        self.iface_tree = ttk.Treeview(iface_frame, columns=columns, show="headings")
        
        for col in columns:
            self.iface_tree.heading(col, text=col.capitalize())
            self.iface_tree.column(col, width=100)
        
        self.iface_tree.column("name", width=150)
        self.iface_tree.column("ip", width=150)
        self.iface_tree.pack(fill="x")
        
        scrollbar = ttk.Scrollbar(iface_frame, orient="horizontal", command=self.iface_tree.xview)
        scrollbar.pack(side="bottom", fill="x")
        self.iface_tree.configure(xscrollcommand=scrollbar.set)
        
        # Top Network Processes
        top_process_frame = ttk.LabelFrame(net_frame, text="Top Network Processes")
        top_process_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("pid", "name", "connections", "user")
        self.top_net_tree = ttk.Treeview(top_process_frame, columns=columns, show="headings")
        
        for col in columns:
            self.top_net_tree.heading(col, text=col.capitalize())
            self.top_net_tree.column(col, width=100)
        
        self.top_net_tree.column("name", width=200)
        self.top_net_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(top_process_frame, orient="vertical", command=self.top_net_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.top_net_tree.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(net_frame, text="Refresh", command=self.update_network_info).pack(side="bottom", pady=5)

    def update_metrics(self):
        prev_disk_io = psutil.disk_io_counters()
        prev_net_io = psutil.net_io_counters()
        
        while self.running:
            # CPU Metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            per_cpu = psutil.cpu_percent(interval=1, percpu=True)
            self.cpu_history.append(cpu_percent)
            
            # Memory Metrics
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            self.memory_history.append(mem.percent)
            
            # Disk Metrics
            disk_io = psutil.disk_io_counters()
            read_speed = (disk_io.read_bytes - prev_disk_io.read_bytes) / 1024 / 1024
            write_speed = (disk_io.write_bytes - prev_disk_io.write_bytes) / 1024 / 1024
            disk_queue = psutil.disk_io_counters().busy_time / 1000
            self.disk_history.append((read_speed, write_speed, disk_queue))
            prev_disk_io = disk_io
            
            # Network Metrics
            net_io = psutil.net_io_counters()
            sent_speed = (net_io.bytes_sent - prev_net_io.bytes_sent) / 1024 / 1024
            recv_speed = (net_io.bytes_recv - prev_net_io.bytes_recv) / 1024 / 1024
            conn_count = len(psutil.net_connections())
            self.network_history.append((sent_speed, recv_speed, conn_count))
            prev_net_io = net_io
            
            # Update UI
            self.root.after(0, self.update_ui, cpu_percent, per_cpu, mem, swap, 
                          read_speed, write_speed, disk_queue,
                          sent_speed, recv_speed, conn_count)
            
            time.sleep(1)

    def update_ui(self, cpu_percent, per_cpu, mem, swap, 
                 read_speed, write_speed, disk_queue,
                 sent_speed, recv_speed, conn_count):
        # Update CPU Tab
        for i, percent in enumerate(per_cpu):
            self.update_progress_bar(self.core_bars[i], percent)
        
        # Update CPU history graph
        self.cpu_line.set_data(range(len(self.cpu_history)), list(self.cpu_history))
        self.cpu_ax.relim()
        self.cpu_ax.autoscale_view(True, True, True)
        self.cpu_canvas.draw()
        
        # Update Memory Tab
        self.update_progress_bar(self.mem_canvas, mem.percent, width=30)
        
        # Update memory pie chart
        buffers = mem.buffers / 1024 / 1024
        cached = mem.cached / 1024 / 1024
        used = (mem.used - mem.buffers - mem.cached) / 1024 / 1024
        free = mem.free / 1024 / 1024
        
        sizes = [used, buffers, cached, free]
        self.mem_ax.clear()
        self.mem_ax.pie(sizes, labels=['Used', 'Buffers', 'Cached', 'Free'], 
                       autopct='%1.1f%%', startangle=90)
        self.mem_ax.set_title("Memory Distribution")
        self.mem_canvas_pie.draw()
        
        # Update swap
        self.update_progress_bar(self.swap_canvas, swap.percent, width=20)
        
        # Update Disk Tab
        if len(self.disk_history) > 0:
            x = range(len(self.disk_history))
            read_data = [h[0] for h in self.disk_history]
            write_data = [h[1] for h in self.disk_history]
            queue_data = [h[2] for h in self.disk_history]
            
            self.disk_read_line.set_data(x, read_data)
            self.disk_write_line.set_data(x, write_data)
            self.disk_queue_line.set_data(x, queue_data)
            
            self.disk_ax1.relim()
            self.disk_ax1.autoscale_view(True, True, True)
            self.disk_ax2.relim()
            self.disk_ax2.autoscale_view(True, True, True)
            self.disk_canvas.draw()
        
        # Update Network Tab
        if len(self.network_history) > 0:
            x = range(len(self.network_history))
            sent_data = [h[0] for h in self.network_history]
            recv_data = [h[1] for h in self.network_history]
            conn_data = [h[2] for h in self.network_history]
            
            self.net_sent_line.set_data(x, sent_data)
            self.net_recv_line.set_data(x, recv_data)
            self.net_conn_line.set_data(x, conn_data)
            
            self.net_ax1.relim()
            self.net_ax1.autoscale_view(True, True, True)
            self.net_ax2.relim()
            self.net_ax2.autoscale_view(True, True, True)
            self.net_canvas.draw()

    def update_progress_bar(self, canvas, percent, width=20):
        canvas.delete("all")
        fill_width = int(canvas.winfo_width() * percent / 100)
        
        if percent < 60:
            color = 'green'
        elif percent < 90:
            color = 'yellow'
        else:
            color = 'red'
        
        canvas.create_rectangle(0, 0, fill_width, width, fill=color, outline='')
        canvas.create_text(canvas.winfo_width()//2, width//2, 
                         text=f"{percent:.1f}%", fill='black')

    def update_top_cpu_processes(self):
        self.top_cpu_tree.delete(*self.top_cpu_tree.get_children())
        for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent', 'username']), 
                          key=lambda p: p.info['cpu_percent'], reverse=True)[:10]:
            try:
                self.top_cpu_tree.insert("", "end", values=(
                    proc.info['pid'],
                    proc.info['name'],
                    f"{proc.info['cpu_percent']:.1f}",
                    proc.info['username'] or 'N/A'
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def update_top_mem_processes(self):
        self.top_mem_tree.delete(*self.top_mem_tree.get_children())
        for proc in sorted(psutil.process_iter(['pid', 'name', 'memory_percent', 'memory_info', 'username']), 
                          key=lambda p: p.info['memory_percent'], reverse=True)[:10]:
            try:
                self.top_mem_tree.insert("", "end", values=(
                    proc.info['pid'],
                    proc.info['name'],
                    f"{proc.info['memory_percent']:.1f}",
                    f"{proc.info['memory_info'].rss / 1024 / 1024:.1f}",
                    proc.info['username'] or 'N/A'
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def update_disk_info(self):
        self.part_tree.delete(*self.part_tree.get_children())
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                self.part_tree.insert("", "end", values=(
                    part.device,
                    part.mountpoint,
                    part.fstype,
                    f"{usage.total / 1024 / 1024:.1f} MB",
                    f"{usage.used / 1024 / 1024:.1f} MB",
                    f"{usage.free / 1024 / 1024:.1f} MB",
                    f"{usage.percent}%"
                ))
            except:
                continue
        
        self.top_disk_tree.delete(*self.top_disk_tree.get_children())
        for proc in psutil.process_iter(['pid', 'name', 'io_counters', 'username']):
            try:
                io = proc.info['io_counters']
                if io.read_bytes > 0 or io.write_bytes > 0:
                    self.top_disk_tree.insert("", "end", values=(
                        proc.info['pid'],
                        proc.info['name'],
                        f"{io.read_bytes / 1024 / 1024:.1f} MB",
                        f"{io.write_bytes / 1024 / 1024:.1f} MB",
                        proc.info['username'] or 'N/A'
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    def update_network_info(self):
        self.iface_tree.delete(*self.iface_tree.get_children())
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            ip = next((addr.address for addr in addrs if addr.family == 2), 'N/A')
            speed = stats.speed if stats else 0
            self.iface_tree.insert("", "end", values=(
                name,
                ip,
                "N/A",
                "N/A",
                f"{speed} Mbps" if speed > 0 else "N/A"
            ))
        
        self.top_net_tree.delete(*self.top_net_tree.get_children())
        conn_counts = {}
        for conn in psutil.net_connections():
            try:
                if conn.pid:
                    conn_counts[conn.pid] = conn_counts.get(conn.pid, 0) + 1
            except:
                continue
        
        for pid, count in sorted(conn_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            try:
                proc = psutil.Process(pid)
                self.top_net_tree.insert("", "end", values=(
                    pid,
                    proc.name(),
                    count,
                    proc.username()
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

    # ====================== PROCESS MANAGEMENT FUNCTIONS ======================
    def init_process_control_tab(self):
        process_frame = ttk.LabelFrame(self.tab_process, text="Running Processes")
        process_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("pid", "name", "status", "cpu", "memory", "user")
        self.process_tree = ttk.Treeview(process_frame, columns=columns, show="headings")
        
        for col in columns:
            self.process_tree.heading(col, text=col.capitalize())
            self.process_tree.column(col, width=100)
        
        self.process_tree.column("name", width=200)
        self.process_tree.column("user", width=150)
        self.process_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(process_frame, orient="vertical", command=self.process_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        control_frame = ttk.Frame(self.tab_process)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_process_list).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Kill Process", command=self.kill_process).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Terminate Process", command=self.terminate_process).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Change Priority", command=self.change_priority).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Pause/Resume", command=self.pause_resume_process).pack(side="left", padx=5)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        ttk.Label(self.tab_process, textvariable=self.status_var).pack(side="bottom", fill="x", padx=10, pady=5)

    def init_alert_system_tab(self):
        threshold_frame = ttk.LabelFrame(self.tab_alerts, text="Alert Thresholds")
        threshold_frame.pack(fill="x", padx=10, pady=10)
        
        # Initialize threshold variables
        self.cpu_threshold = tk.IntVar(value=self.thresholds['cpu'])
        self.memory_threshold = tk.IntVar(value=self.thresholds['memory'])
        self.process_count_threshold = tk.IntVar(value=self.thresholds['process_count'])
        self.zombie_threshold = tk.IntVar(value=self.thresholds['zombie_processes'])
        
        # CPU threshold
        ttk.Label(threshold_frame, text="CPU Usage (%):").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        ttk.Entry(threshold_frame, textvariable=self.cpu_threshold, width=5).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        # Memory threshold
        ttk.Label(threshold_frame, text="Memory Usage (%):").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        ttk.Entry(threshold_frame, textvariable=self.memory_threshold, width=5).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Process count threshold
        ttk.Label(threshold_frame, text="Process Count:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        ttk.Entry(threshold_frame, textvariable=self.process_count_threshold, width=5).grid(row=2, column=1, padx=5, pady=5, sticky="w")
        
        # Zombie process threshold
        ttk.Label(threshold_frame, text="Zombie Processes:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        ttk.Entry(threshold_frame, textvariable=self.zombie_threshold, width=5).grid(row=3, column=1, padx=5, pady=5, sticky="w")
        
        # Save button
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

    def save_thresholds(self):
        """Save the current threshold settings to the configuration"""
        self.thresholds = {
            'cpu': self.cpu_threshold.get(),
            'memory': self.memory_threshold.get(),
            'process_count': self.process_count_threshold.get(),
            'zombie_processes': self.zombie_threshold.get()
        }
        self.save_settings()
        messagebox.showinfo("Success", "Threshold settings saved")

    def init_automation_rules_tab(self):
        rules_frame = ttk.LabelFrame(self.tab_rules, text="Automation Rules")
        rules_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        columns = ("id", "condition", "action", "target", "active")
        self.rules_tree = ttk.Treeview(rules_frame, columns=columns, show="headings")
        
        for col in columns:
            self.rules_tree.heading(col, text=col.capitalize())
            self.rules_tree.column(col, width=100)
        
        self.rules_tree.column("condition", width=200)
        self.rules_tree.column("action", width=150)
        self.rules_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(rules_frame, orient="vertical", command=self.rules_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.rules_tree.configure(yscrollcommand=scrollbar.set)
        
        control_frame = ttk.Frame(self.tab_rules)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Add Rule", command=self.add_rule).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Edit Rule", command=self.edit_rule).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Delete Rule", command=self.delete_rule).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Toggle Active", command=self.toggle_rule_active).pack(side="left", padx=5)
        
        self.rules_status_var = tk.StringVar()
        self.rules_status_var.set("Ready")
        ttk.Label(self.tab_rules, textvariable=self.rules_status_var).pack(side="bottom", fill="x", padx=10, pady=5)

    def init_reporting_tab(self):
        report_frame = ttk.LabelFrame(self.tab_reports, text="Generate Reports")
        report_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(report_frame, text="Resource Usage Report", command=self.generate_resource_report).pack(side="left", padx=5, pady=5)
        ttk.Button(report_frame, text="Process List Report", command=self.generate_process_report).pack(side="left", padx=5, pady=5)
        ttk.Button(report_frame, text="System Event Log", command=self.generate_event_log).pack(side="left", padx=5, pady=5)
        
        display_frame = ttk.LabelFrame(self.tab_reports, text="Report Output")
        display_frame.pack(fill="both", expand=True, padx=10, pady=10)
        self.report_text = tk.Text(display_frame, wrap="word", state="disabled")
        self.report_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(display_frame, orient="vertical", command=self.report_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.report_text.configure(yscrollcommand=scrollbar.set)
        
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

    def log_alert(self, message, alert_type="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{alert_type}] {message}\n"
        
        self.alert_log.config(state="normal")
        self.alert_log.insert("end", log_entry)
        self.alert_log.config(state="disabled")
        self.alert_log.see("end")
        
        if alert_type in ("WARNING", "ERROR"):
            self.root.attributes("-topmost", True)
            self.root.after(100, lambda: self.root.attributes("-topmost", False))

    def clear_alert_log(self):
        self.alert_log.config(state="normal")
        self.alert_log.delete("1.0", "end")
        self.alert_log.config(state="disabled")

    def add_rule(self):
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
            with open('system_monitor_settings.json', 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            self.log_alert(f"Failed to save settings: {str(e)}", "ERROR")

    def load_settings(self):
        if os.path.exists('system_monitor_settings.json'):
            try:
                with open('system_monitor_settings.json', 'r') as f:
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
    app = SystemMonitor(root)
    root.mainloop()
