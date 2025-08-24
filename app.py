import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from datetime import datetime
import hashlib
import re

class UserManager:
    def __init__(self):
        self.users_file = "users.json"
        self.current_user = None
        self.users = self.load_users()
    
    def load_users(self):
        if os.path.exists(self.users_file):
            try:
                with open(self.users_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return {}
        return {}
    
    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f, indent=2)
    
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    def register(self, username, email, password, confirm_password):
        if not username or not email or not password:
            return False, "All fields are required!"
        
        if not self.validate_email(email):
            return False, "Please enter a valid email address!"
        
        if len(password) < 6:
            return False, "Password must be at least 6 characters!"
        
        if password != confirm_password:
            return False, "Passwords do not match!"
        
        if username in self.users:
            return False, "Username already exists!"
        
        for user in self.users.values():
            if user['email'] == email:
                return False, "Email already registered!"
        
        self.users[username] = {
            'email': email,
            'password': self.hash_password(password),
            'created_at': datetime.now().isoformat()
        }
        
        self.save_users()
        return True, "Registration successful!"
    
    def login(self, username, password):
        if not username or not password:
            return False, "Please enter both username and password!"
        
        if username not in self.users:
            return False, "Invalid username or password!"
        
        if self.users[username]['password'] != self.hash_password(password):
            return False, "Invalid username or password!"
        
        self.current_user = username
        return True, "Login successful!"


class ModernTodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Modern Todo App")
        self.root.geometry("800x600")
        self.root.configure(bg="#f5f7ff")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.bg_color = "#ffffff"
        self.accent_color = "#5b6bf0"
        self.secondary_color = "#7e8ef1"
        self.completed_color = "#a0a0a0"
        self.high_priority_color = "#ff6b6b"
        self.medium_priority_color = "#ff9e43"
        self.low_priority_color = "#4cd97b"
        self.text_color = "#2d3748"
        self.light_text = "#718096"
        
        # Initialize user manager
        self.user_manager = UserManager()
        
        # Show login screen initially
        self.show_login_screen()
    
    def show_login_screen(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container
        container = ttk.Frame(self.root, padding=30)
        container.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(container)
        header_frame.pack(pady=(50, 30))
        
        ttk.Label(header_frame, text="Welcome Back", 
                 font=("Segoe UI", 24, "bold"), 
                 foreground=self.accent_color).pack()
        
        ttk.Label(header_frame, text="Sign in to your account", 
                 font=("Segoe UI", 12), 
                 foreground=self.light_text).pack(pady=(5, 0))
        
        # Login form
        form_frame = ttk.Frame(container)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, text="Username", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=(10, 5))
        self.username_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 11))
        self.username_entry.grid(row=1, column=0, pady=(0, 15), ipady=5)
        
        ttk.Label(form_frame, text="Password", font=("Segoe UI", 10, "bold")).grid(
            row=2, column=0, sticky=tk.W, pady=(10, 5))
        self.password_entry = ttk.Entry(form_frame, width=30, show="•", font=("Segoe UI", 11))
        self.password_entry.grid(row=3, column=0, pady=(0, 20), ipady=5)
        
        # Login button
        login_btn = ttk.Button(form_frame, text="Sign In", 
                              command=self.handle_login, 
                              style="Accent.TButton")
        login_btn.grid(row=4, column=0, pady=10, ipady=8, sticky=tk.EW)
        
        # Register link
        register_frame = ttk.Frame(container)
        register_frame.pack(pady=10)
        
        ttk.Label(register_frame, text="Don't have an account?", 
                 font=("Segoe UI", 10), 
                 foreground=self.light_text).pack(side=tk.LEFT)
        
        register_link = ttk.Label(register_frame, text="Sign up", 
                                 font=("Segoe UI", 10, "bold"), 
                                 foreground=self.accent_color,
                                 cursor="hand2")
        register_link.pack(side=tk.LEFT, padx=5)
        register_link.bind("<Button-1>", lambda e: self.show_register_screen())
        
        # Configure styles
        self.style.configure("Accent.TButton", 
                            background=self.accent_color, 
                            foreground="white",
                            font=("Segoe UI", 10, "bold"),
                            padding=(20, 10))
        
        self.style.map("Accent.TButton",
                      background=[('active', self.secondary_color)])
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda e: self.handle_login())
        
        # Focus on username field
        self.username_entry.focus()
    
    def show_register_screen(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container
        container = ttk.Frame(self.root, padding=30)
        container.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(container)
        header_frame.pack(pady=(30, 20))
        
        ttk.Label(header_frame, text="Create Account", 
                 font=("Segoe UI", 24, "bold"), 
                 foreground=self.accent_color).pack()
        
        ttk.Label(header_frame, text="Sign up to get started", 
                 font=("Segoe UI", 12), 
                 foreground=self.light_text).pack(pady=(5, 0))
        
        # Registration form
        form_frame = ttk.Frame(container)
        form_frame.pack(pady=20)
        
        ttk.Label(form_frame, text="Username", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=(10, 5))
        self.reg_username_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 11))
        self.reg_username_entry.grid(row=1, column=0, pady=(0, 10), ipady=5)
        
        ttk.Label(form_frame, text="Email", font=("Segoe UI", 10, "bold")).grid(
            row=2, column=0, sticky=tk.W, pady=(10, 5))
        self.email_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 11))
        self.email_entry.grid(row=3, column=0, pady=(0, 10), ipady=5)
        
        ttk.Label(form_frame, text="Password", font=("Segoe UI", 10, "bold")).grid(
            row=4, column=0, sticky=tk.W, pady=(10, 5))
        self.reg_password_entry = ttk.Entry(form_frame, width=30, show="•", font=("Segoe UI", 11))
        self.reg_password_entry.grid(row=5, column=0, pady=(0, 10), ipady=5)
        
        ttk.Label(form_frame, text="Confirm Password", font=("Segoe UI", 10, "bold")).grid(
            row=6, column=0, sticky=tk.W, pady=(10, 5))
        self.confirm_password_entry = ttk.Entry(form_frame, width=30, show="•", font=("Segoe UI", 11))
        self.confirm_password_entry.grid(row=7, column=0, pady=(0, 20), ipady=5)
        
        # Register button
        register_btn = ttk.Button(form_frame, text="Create Account", 
                                 command=self.handle_register, 
                                 style="Accent.TButton")
        register_btn.grid(row=8, column=0, pady=10, ipady=8, sticky=tk.EW)
        
        # Login link
        login_frame = ttk.Frame(container)
        login_frame.pack(pady=10)
        
        ttk.Label(login_frame, text="Already have an account?", 
                 font=("Segoe UI", 10), 
                 foreground=self.light_text).pack(side=tk.LEFT)
        
        login_link = ttk.Label(login_frame, text="Sign in", 
                              font=("Segoe UI", 10, "bold"), 
                              foreground=self.accent_color,
                              cursor="hand2")
        login_link.pack(side=tk.LEFT, padx=5)
        login_link.bind("<Button-1>", lambda e: self.show_login_screen())
        
        # Bind Enter key to register
        self.root.bind('<Return>', lambda e: self.handle_register())
        
        # Focus on username field
        self.reg_username_entry.focus()
    
    def show_todo_app(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Configure main window
        self.root.geometry("900x650")
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header with user info
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="Modern Todo App", 
                 font=("Segoe UI", 18, "bold"), 
                 foreground=self.accent_color).pack(side=tk.LEFT)
        
        # User info and logout button
        user_frame = ttk.Frame(header_frame)
        user_frame.pack(side=tk.RIGHT)
        
        ttk.Label(user_frame, text=f"Welcome, {self.user_manager.current_user}", 
                 font=("Segoe UI", 10), 
                 foreground=self.light_text).pack(side=tk.LEFT, padx=(0, 10))
        
        logout_btn = ttk.Button(user_frame, text="Logout", 
                               command=self.logout,
                               style="Secondary.TButton")
        logout_btn.pack(side=tk.RIGHT)
        
        # Add task section
        add_frame = ttk.LabelFrame(main_frame, text="Add New Task", padding=15)
        add_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Task entry
        ttk.Label(add_frame, text="Task:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.task_entry = ttk.Entry(add_frame, width=40, font=("Segoe UI", 11))
        self.task_entry.grid(row=0, column=1, padx=(0, 15), ipady=4)
        self.task_entry.bind("<Return>", lambda e: self.add_todo())
        
        # Priority selection
        ttk.Label(add_frame, text="Priority:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.priority_var = tk.StringVar(value="Medium")
        priority_combo = ttk.Combobox(add_frame, textvariable=self.priority_var, 
                                     values=["High", "Medium", "Low"], width=10, 
                                     state="readonly", font=("Segoe UI", 10))
        priority_combo.grid(row=0, column=3, padx=(0, 15))
        
        # Add button
        add_btn = ttk.Button(add_frame, text="Add Task", 
                            command=self.add_todo, 
                            style="Accent.TButton")
        add_btn.grid(row=0, column=4)
        
        # Task list
        list_frame = ttk.LabelFrame(main_frame, text="Your Tasks", padding=15)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a frame for the listbox and scrollbar
        listbox_frame = ttk.Frame(list_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        # Listbox with scrollbar
        self.listbox = tk.Listbox(listbox_frame, selectmode=tk.SINGLE, 
                                 font=("Segoe UI", 11), 
                                 relief=tk.FLAT, highlightthickness=0,
                                 activestyle="none")
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(listbox_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.config(yscrollcommand=scrollbar.set)
        
        # Bind selection event
        self.listbox.bind('<<ListboxSelect>>', self.on_select)
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(15, 0))
        
        # Complete button
        self.complete_btn = ttk.Button(action_frame, text="Mark Complete", 
                                      command=self.complete_todo, 
                                      state=tk.DISABLED,
                                      style="Secondary.TButton")
        self.complete_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Delete button
        self.delete_btn = ttk.Button(action_frame, text="Delete Task", 
                                    command=self.delete_todo, 
                                    state=tk.DISABLED,
                                    style="Secondary.TButton")
        self.delete_btn.pack(side=tk.LEFT, padx=10)
        
        # Clear completed button
        clear_btn = ttk.Button(action_frame, text="Clear Completed", 
                              command=self.clear_completed,
                              style="Secondary.TButton")
        clear_btn.pack(side=tk.RIGHT)
        
        # Configure styles
        self.style.configure("Secondary.TButton", 
                            background="#e9ecef", 
                            foreground=self.text_color,
                            font=("Segoe UI", 10),
                            padding=(10, 5))
        
        self.style.map("Secondary.TButton",
                      background=[('active', "#dde1e6")])
        
        # Load user's todos
        self.todos = self.load_todos()
        self.update_todo_list()
        
        # Bind Enter key to add task
        self.root.bind('<Return>', lambda e: self.add_todo())
    
    def handle_login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        success, message = self.user_manager.login(username, password)
        
        if success:
            messagebox.showinfo("Success", message)
            self.show_todo_app()
        else:
            messagebox.showerror("Error", message)
    
    def handle_register(self):
        username = self.reg_username_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.reg_password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        
        success, message = self.user_manager.register(username, email, password, confirm_password)
        
        if success:
            messagebox.showinfo("Success", message)
            self.show_login_screen()
        else:
            messagebox.showerror("Error", message)
    
    def logout(self):
        self.user_manager.current_user = None
        self.show_login_screen()
    
    def get_user_todos_file(self):
        return f"todos_{self.user_manager.current_user}.json"
    
    def load_todos(self):
        filename = self.get_user_todos_file()
        if os.path.exists(filename):
            try:
                with open(filename, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return []
        return []
    
    def save_todos(self):
        filename = self.get_user_todos_file()
        with open(filename, 'w') as f:
            json.dump(self.todos, f, indent=2)
    
    def add_todo(self):
        task = self.task_entry.get().strip()
        if not task:
            messagebox.showwarning("Input Error", "Please enter a task!")
            return
            
        priority = self.priority_var.get()
        
        todo = {
            'id': len(self.todos) + 1,
            'task': task,
            'priority': priority,
            'completed': False,
            'created_at': datetime.now().isoformat()
        }
        
        self.todos.append(todo)
        self.save_todos()
        self.update_todo_list()
        
        # Clear the entry field
        self.task_entry.delete(0, tk.END)
    
    def update_todo_list(self):
        self.listbox.delete(0, tk.END)
        
        for todo in self.todos:
            prefix = "✓ " if todo['completed'] else "□ "
            
            # Color coding based on priority and completion status
            if todo['completed']:
                color = self.completed_color
            else:
                if todo['priority'] == "High":
                    color = self.high_priority_color
                elif todo['priority'] == "Medium":
                    color = self.medium_priority_color
                else:
                    color = self.low_priority_color
            
            display_text = f"{prefix}{todo['task']} ({todo['priority']})"
            self.listbox.insert(tk.END, display_text)
            
            # Apply color based on status and priority
            if todo['completed']:
                self.listbox.itemconfig(tk.END, {'fg': self.completed_color})
            else:
                self.listbox.itemconfig(tk.END, {'fg': color})
    
    def on_select(self, event):
        if not self.listbox.curselection():
            return
            
        index = self.listbox.curselection()[0]
        if index < len(self.todos):
            self.complete_btn.config(state=tk.NORMAL)
            self.delete_btn.config(state=tk.NORMAL)
    
    def complete_todo(self):
        selection = self.listbox.curselection()
        if not selection:
            return
            
        index = selection[0]
        if index < len(self.todos):
            self.todos[index]['completed'] = True
            self.todos[index]['completed_at'] = datetime.now().isoformat()
            self.save_todos()
            self.update_todo_list()
            
            # Disable buttons after completion
            self.complete_btn.config(state=tk.DISABLED)
            self.delete_btn.config(state=tk.DISABLED)
    
    def delete_todo(self):
        selection = self.listbox.curselection()
        if not selection:
            return
            
        index = selection[0]
        if index < len(self.todos):
            # Confirm deletion
            if messagebox.askyesno("Confirm Delete", 
                                  f"Are you sure you want to delete '{self.todos[index]['task']}'?"):
                del self.todos[index]
                self.save_todos()
                self.update_todo_list()
                
                # Disable buttons after deletion
                self.complete_btn.config(state=tk.DISABLED)
                self.delete_btn.config(state=tk.DISABLED)
    
    def clear_completed(self):
        # Confirm clearing completed tasks
        if messagebox.askyesno("Confirm Clear", 
                              "Are you sure you want to clear all completed tasks?"):
            self.todos = [todo for todo in self.todos if not todo['completed']]
            self.save_todos()
            self.update_todo_list()


if __name__ == "__main__":
    root = tk.Tk()
    app = ModernTodoApp(root)
    root.mainloop()