import tkinter as tk
from tkinter import ttk
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time
import threading
from collections import deque

class SystemResourceMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("System Resource Monitor")
        self.root.geometry("1400x900")
        
        # Data storage for historical metrics
        self.cpu_history = deque(maxlen=60)  # Store 60 data points (1 minute at 1s intervals)
        self.memory_history = deque(maxlen=60)
        self.disk_history = deque(maxlen=60)
        self.network_history = deque(maxlen=60)
        
        # Create tabs
        self.tab_control = ttk.Notebook(root)
        
        # CPU Tab
        self.tab_cpu = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_cpu, text='CPU Monitor')
        
        # Memory Tab
        self.tab_memory = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_memory, text='Memory Monitor')
        
        # Disk Tab
        self.tab_disk = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_disk, text='Disk Monitor')
        
        # Network Tab
        self.tab_network = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_network, text='Network Monitor')
        
        self.tab_control.pack(expand=1, fill="both")
        
        # Initialize all tabs
        self.init_cpu_tab()
        self.init_memory_tab()
        self.init_disk_tab()
        self.init_network_tab()
        
        # Start the monitoring thread
        self.running = True
        self.monitor_thread = threading.Thread(target=self.update_metrics)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def init_cpu_tab(self):
        # CPU Usage Frame
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
        # Memory Usage Frame
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
        self.top_mem_tree.heading("rss", text="RSS (MB)")  # Correct
        
        self.top_mem_tree.pack(fill="both", expand=True)
        
        scrollbar = ttk.Scrollbar(top_process_frame, orient="vertical", command=self.top_mem_tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.top_mem_tree.configure(yscrollcommand=scrollbar.set)
        
        ttk.Button(mem_frame, text="Refresh", command=self.update_top_mem_processes).pack(side="bottom", pady=5)
    
    def init_disk_tab(self):
        # Disk I/O Frame
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
        # Network Frame
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
            read_speed = (disk_io.read_bytes - prev_disk_io.read_bytes) / 1024 / 1024  # MB/s
            write_speed = (disk_io.write_bytes - prev_disk_io.write_bytes) / 1024 / 1024  # MB/s
            disk_queue = psutil.disk_io_counters().busy_time / 1000  # Simplified queue length
            self.disk_history.append((read_speed, write_speed, disk_queue))
            prev_disk_io = disk_io
            
            # Network Metrics
            net_io = psutil.net_io_counters()
            sent_speed = (net_io.bytes_sent - prev_net_io.bytes_sent) / 1024 / 1024  # MB/s
            recv_speed = (net_io.bytes_recv - prev_net_io.bytes_recv) / 1024 / 1024  # MB/s
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
        buffers = mem.buffers / 1024 / 1024  # MB
        cached = mem.cached / 1024 / 1024  # MB
        used = (mem.used - mem.buffers - mem.cached) / 1024 / 1024  # MB
        free = mem.free / 1024 / 1024  # MB
        
        sizes = [used, buffers, cached, free]
        self.mem_ax.clear()
        self.mem_ax.pie(sizes, labels=['Used', 'Buffers', 'Cached', 'Free'], 
                       autopct='%1.1f%%', startangle=90)
        self.mem_ax.set_title("Memory Distribution")
        self.mem_canvas_pie.draw()
        
        # Update swap
        self.update_progress_bar(self.swap_canvas, swap.percent, width=20)
        
        # Update Disk Tab
        # Update disk throughput graph
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
        # Update network graph
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
        # Update disk partitions
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
        
        # Update top disk processes
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
        # Update network interfaces
        self.iface_tree.delete(*self.iface_tree.get_children())
        for name, addrs in psutil.net_if_addrs().items():
            stats = psutil.net_if_stats().get(name)
            ip = next((addr.address for addr in addrs if addr.family == 2), 'N/A')  # AF_INET
            speed = stats.speed if stats else 0
            self.iface_tree.insert("", "end", values=(
                name,
                ip,
                "N/A",  # Would need to track sent/recv per interface
                "N/A",
                f"{speed} Mbps" if speed > 0 else "N/A"
            ))
        
        # Update top network processes
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
    
    def on_closing(self):
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SystemResourceMonitor(root)
    root.mainloop()
