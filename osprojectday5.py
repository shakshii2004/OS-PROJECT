import tkinter as tk
from tkinter import ttk, messagebox
import psutil
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import time
import os
import signal

class ProcessMonitor:
    def __init__(self, root):
        self.root = root
        self.root.title("Process State Monitor")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("Treeview", rowheight=25)
        self.style.map('Treeview', background=[('selected', '#347083')])
        
        # Create main containers
        self.top_frame = ttk.Frame(root)
        self.top_frame.pack(fill=tk.X)
        
        self.middle_frame = ttk.Frame(root)
        self.middle_frame.pack(fill=tk.BOTH, expand=True)
        
        self.bottom_frame = ttk.Frame(root)
        self.bottom_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create filter controls
        self.create_filters()
        
        # Create process table
        self.create_process_table()
        
        # Create pie chart
        self.create_pie_chart()
        
        # Create process tree
        self.create_process_tree()
        
        # Start updates
        self.update_interval = 2000  # 2 seconds
        self.update_data()

    def create_filters(self):
        filter_frame = ttk.LabelFrame(self.top_frame, text="Filters")
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # User filter
        ttk.Label(filter_frame, text="User:").grid(row=0, column=0, padx=5)
        self.user_filter = ttk.Combobox(filter_frame, state='readonly')
        self.user_filter.grid(row=0, column=1, padx=5)
        
        # State filter
        ttk.Label(filter_frame, text="State:").grid(row=0, column=2, padx=5)
        self.state_filter = ttk.Combobox(filter_frame, state='readonly')
        self.state_filter.grid(row=0, column=3, padx=5)
        
        # Search filter
        ttk.Label(filter_frame, text="Search:").grid(row=0, column=4, padx=5)
        self.search_filter = ttk.Entry(filter_frame)
        self.search_filter.grid(row=0, column=5, padx=5)
        self.search_filter.bind('<KeyRelease>', lambda e: self.update_data())

    def create_process_table(self):
        container = ttk.LabelFrame(self.middle_frame, text="Process Table")
        container.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        columns = ('pid', 'name', 'user', 'state')
        self.tree = ttk.Treeview(container, columns=columns, show='headings', selectmode='browse')
        
        # Configure columns
        self.tree.heading('pid', text='PID', command=lambda: self.sort_column('pid', False))
        self.tree.heading('name', text='Name', command=lambda: self.sort_column('name', False))
        self.tree.heading('user', text='User', command=lambda: self.sort_column('user', False))
        self.tree.heading('state', text='State', command=lambda: self.sort_column('state', False))
        
        self.tree.column('pid', width=80, anchor=tk.CENTER)
        self.tree.column('name', width=150)
        self.tree.column('user', width=100)
        self.tree.column('state', width=100)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Kill Process", command=self.kill_selected_process)
        self.context_menu.add_command(label="Show Process Tree", command=self.show_process_tree)
        self.tree.bind('<Button-3>', self.show_context_menu)

    def create_pie_chart(self):
        container = ttk.LabelFrame(self.middle_frame, text="State Distribution")
        container.pack(side=tk.LEFT, fill=tk.BOTH, padx=5, pady=5)
        
        fig = Figure(figsize=(5, 4), dpi=100)
        self.pie_ax = fig.add_subplot(111)
        self.pie_chart = FigureCanvasTkAgg(fig, master=container)
        self.pie_chart.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def create_process_tree(self):
        container = ttk.LabelFrame(self.bottom_frame, text="Process Tree")
        container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.tree_view = ttk.Treeview(container)
        self.tree_view.pack(fill=tk.BOTH, expand=True)

    def get_process_data(self):
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'status']):
            try:
                processes.append({
                    'pid': proc.pid,
                    'name': proc.name(),
                    'user': proc.username(),
                    'state': proc.status(),
                    'parent_pid': proc.ppid()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def update_data(self):
        processes = self.get_process_data()
        
        # Update filters
        users = list(sorted({p['user'] for p in processes}))
        self.user_filter['values'] = ['All'] + users
        
        states = list(sorted({p['state'] for p in processes}))
        self.state_filter['values'] = ['All'] + states
        
        # Apply filters
        selected_user = self.user_filter.get()
        if selected_user and selected_user != 'All':
            processes = [p for p in processes if p['user'] == selected_user]
            
        selected_state = self.state_filter.get()
        if selected_state and selected_state != 'All':
            processes = [p for p in processes if p['state'] == selected_state]
            
        search_term = self.search_filter.get().lower()
        if search_term:
            processes = [p for p in processes if search_term in p['name'].lower()]
        
        # Update process table
        self.update_table(processes)
        
        # Update pie chart
        self.update_pie_chart(processes)
        
        # Update process tree
        self.update_process_tree(processes)
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_data)

    def update_table(self, processes):
        self.tree.delete(*self.tree.get_children())
        for p in processes:
            state = p['state']
            tags = ()
            if state == 'running':
                tags = ('running',)
            elif state == 'sleeping':
                tags = ('sleeping',)
            elif state == 'zombie':
                tags = ('zombie',)
            
            self.tree.insert('', 'end', 
                values=(p['pid'], p['name'], p['user'], state),
                tags=tags
            )
        
        # Configure tag colors
        self.tree.tag_configure('running', background='#d4edda')
        self.tree.tag_configure('sleeping', background='#fff3cd')
        self.tree.tag_configure('zombie', background='#f8d7da')

    def update_pie_chart(self, processes):
        self.pie_ax.clear()
        states = {}
        for p in processes:
            states[p['state']] = states.get(p['state'], 0) + 1
        
        if states:
            labels = list(states.keys())
            sizes = list(states.values())
            colors = ['#d4edda' if s == 'running' else 
                     '#fff3cd' if s == 'sleeping' else 
                     '#f8d7da' for s in labels]
            
            self.pie_ax.pie(sizes, labels=labels, colors=colors,
                           autopct='%1.1f%%', startangle=90)
            self.pie_ax.axis('equal')
            self.pie_chart.draw()

    def update_process_tree(self, processes):
        self.tree_view.delete(*self.tree_view.get_children())
        process_map = {p['pid']: p for p in processes}
        
        def add_children(parent_pid, parent_node):
            children = [p for p in processes if p['parent_pid'] == parent_pid]
            for child in children:
                node = self.tree_view.insert(parent_node, 'end', 
                    text=f"{child['name']} (PID: {child['pid']})",
                    values=(child['state'],)
                )
                add_children(child['pid'], node)
        
        # Start with root processes (parent pid not in our list)
        root_processes = [p for p in processes if p['parent_pid'] not in process_map]
        for p in root_processes:
            node = self.tree_view.insert('', 'end', 
                text=f"{p['name']} (PID: {p['pid']})",
                values=(p['state'],)
            )
            add_children(p['pid'], node)

    def sort_column(self, col, reverse):
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children('')]
        data.sort(reverse=reverse)
        
        for index, (val, child) in enumerate(data):
            self.tree.move(child, '', index)
        
        self.tree.heading(col, command=lambda: self.sort_column(col, not reverse))

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def kill_selected_process(self):
        selected = self.tree.selection()
        if selected:
            pid = self.tree.item(selected[0], 'values')[0]
            try:
                os.kill(int(pid), signal.SIGTERM)
                messagebox.showinfo("Success", f"Process {pid} terminated")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def show_process_tree(self):
        selected = self.tree.selection()
        if selected:
            pid = int(self.tree.item(selected[0], 'values')[0])
            # Implement detailed process tree view here

if __name__ == "__main__":
    root = tk.Tk()
    app = ProcessMonitor(root)
    root.geometry("1200x800")
    root.mainloop()
