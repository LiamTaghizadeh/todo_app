import tkinter as tk
from tkinter import ttk, messagebox, font
import json
import os
import webbrowser
from datetime import datetime
import hashlib
import re
import random
import time
import requests
from urllib.parse import urlencode
import base64
import secrets
import string

class OAuthManager:
    """Handles real OAuth authentication flow for Google and GitHub"""
    
    def __init__(self):
        # OAuth configuration - in a real app, these should be stored securely
        self.google_client_id = "YOUR_GOOGLE_CLIENT_ID"  # Replace with your actual Google Client ID
        self.google_client_secret = "YOUR_GOOGLE_CLIENT_SECRET"  # Replace with your actual Google Client Secret
        self.google_redirect_uri = "http://localhost:8080/google-callback"
        
        self.github_client_id = "YOUR_GITHUB_CLIENT_ID"  # Replace with your actual GitHub Client ID
        self.github_client_secret = "YOUR_GITHUB_CLIENT_SECRET"  # Replace with your actual GitHub Client Secret
        self.github_redirect_uri = "http://localhost:8080/github-callback"
        
        # State parameter for CSRF protection
        self.state = self.generate_state()
    
    def generate_state(self):
        """Generate a random state parameter for OAuth"""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    
    def get_google_auth_url(self):
        """Generate Google OAuth URL"""
        params = {
            'client_id': self.google_client_id,
            'redirect_uri': self.google_redirect_uri,
            'response_type': 'code',
            'scope': 'openid email profile',
            'state': self.state,
            'access_type': 'offline',
            'prompt': 'consent'
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"
    
    def get_github_auth_url(self):
        """Generate GitHub OAuth URL"""
        params = {
            'client_id': self.github_client_id,
            'redirect_uri': self.github_redirect_uri,
            'scope': 'user:email',
            'state': self.state
        }
        return f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    
    def exchange_google_code(self, code):
        """Exchange authorization code for access token (Google)"""
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            'client_id': self.google_client_id,
            'client_secret': self.google_client_secret,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.google_redirect_uri
        }
        
        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            return response.json().get('access_token')
        return None
    
    def exchange_github_code(self, code):
        """Exchange authorization code for access token (GitHub)"""
        token_url = "https://github.com/login/oauth/access_token"
        data = {
            'client_id': self.github_client_id,
            'client_secret': self.github_client_secret,
            'code': code,
            'redirect_uri': self.github_redirect_uri
        }
        headers = {
            'Accept': 'application/json'
        }
        
        response = requests.post(token_url, data=data, headers=headers)
        if response.status_code == 200:
            return response.json().get('access_token')
        return None
    
    def get_google_user_info(self, access_token):
        """Get user info from Google using access token"""
        user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo"
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        
        response = requests.get(user_info_url, headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            return {
                'username': user_data.get('email').split('@')[0],
                'email': user_data.get('email'),
                'name': user_data.get('name', ''),
                'provider': 'google'
            }
        return None
    
    def get_github_user_info(self, access_token):
        """Get user info from GitHub using access token"""
        user_info_url = "https://api.github.com/user"
        emails_url = "https://api.github.com/user/emails"
        headers = {
            'Authorization': f'token {access_token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        # Get user profile
        response = requests.get(user_info_url, headers=headers)
        if response.status_code == 200:
            user_data = response.json()
            
            # Get user emails to find primary email
            email_response = requests.get(emails_url, headers=headers)
            email = user_data.get('email', '')
            
            if email_response.status_code == 200:
                emails = email_response.json()
                for em in emails:
                    if em.get('primary'):
                        email = em.get('email')
                        break
            
            return {
                'username': user_data.get('login'),
                'email': email,
                'name': user_data.get('name', user_data.get('login')),
                'provider': 'github'
            }
        return None


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
            'created_at': datetime.now().isoformat(),
            'provider': 'email'
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
    
    def oauth_login(self, user_data):
        """Handle OAuth login/registration"""
        username = user_data['username']
        email = user_data['email']
        provider = user_data['provider']
        
        # If user doesn't exist, create them
        if username not in self.users:
            self.users[username] = {
                'email': email,
                'name': user_data.get('name', ''),
                'created_at': datetime.now().isoformat(),
                'provider': provider
            }
            self.save_users()
        
        self.current_user = username
        return True, f"Logged in with {provider.capitalize()}!"


class ModernTodoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Modern Todo App")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f5f7ff")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure colors
        self.bg_color = "#ffffff"
        self.accent_color = "#5b6bf0"
        self.secondary_color = "#7e8ef1"
        self.google_color = "#DB4437"
        self.github_color = "#24292e"
        self.completed_color = "#a0a0a0"
        self.high_priority_color = "#ff6b6b"
        self.medium_priority_color = "#ff9e43"
        self.low_priority_color = "#4cd97b"
        self.text_color = "#2d3748"
        self.light_text = "#718096"
        
        # Initialize user manager and OAuth manager
        self.user_manager = UserManager()
        self.oauth_manager = OAuthManager()
        
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
        
        # OAuth buttons frame
        oauth_frame = ttk.Frame(container)
        oauth_frame.pack(pady=20, fill=tk.X)
        
        # Google login button
        google_btn = tk.Button(oauth_frame, text="Sign in with Google", 
                              font=("Segoe UI", 10, "bold"),
                              bg=self.google_color, fg="white",
                              relief=tk.FLAT, padx=20, pady=10,
                              cursor="hand2",
                              command=self.handle_google_login)
        google_btn.pack(fill=tk.X, pady=5)
        
        # GitHub login button
        github_btn = tk.Button(oauth_frame, text="Sign in with GitHub", 
                              font=("Segoe UI", 10, "bold"),
                              bg=self.github_color, fg="white",
                              relief=tk.FLAT, padx=20, pady=10,
                              cursor="hand2",
                              command=self.handle_github_login)
        github_btn.pack(fill=tk.X, pady=5)
        
        # Divider
        divider = ttk.Frame(container, height=2, relief=tk.SUNKEN)
        divider.pack(fill=tk.X, pady=20)
        
        # Login form
        form_frame = ttk.Frame(container)
        form_frame.pack(pady=20, fill=tk.X)
        
        ttk.Label(form_frame, text="Username", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=(10, 5))
        self.username_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 11))
        self.username_entry.grid(row=1, column=0, pady=(0, 15), ipady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Password", font=("Segoe UI", 10, "bold")).grid(
            row=2, column=0, sticky=tk.W, pady=(10, 5))
        self.password_entry = ttk.Entry(form_frame, width=30, show="•", font=("Segoe UI", 11))
        self.password_entry.grid(row=3, column=0, pady=(0, 20), ipady=5, sticky=tk.EW)
        
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
        
        # Configure column weight for responsive design
        form_frame.columnconfigure(0, weight=1)
        
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
        
        # OAuth buttons frame
        oauth_frame = ttk.Frame(container)
        oauth_frame.pack(pady=20, fill=tk.X)
        
        # Google signup button
        google_btn = tk.Button(oauth_frame, text="Sign up with Google", 
                              font=("Segoe UI", 10, "bold"),
                              bg=self.google_color, fg="white",
                              relief=tk.FLAT, padx=20, pady=10,
                              cursor="hand2",
                              command=self.handle_google_login)
        google_btn.pack(fill=tk.X, pady=5)
        
        # GitHub signup button
        github_btn = tk.Button(oauth_frame, text="Sign up with GitHub", 
                              font=("Segoe UI", 10, "bold"),
                              bg=self.github_color, fg="white",
                              relief=tk.FLAT, padx=20, pady=10,
                              cursor="hand2",
                              command=self.handle_github_login)
        github_btn.pack(fill=tk.X, pady=5)
        
        # Divider
        divider = ttk.Frame(container, height=2, relief=tk.SUNKEN)
        divider.pack(fill=tk.X, pady=20)
        
        # Registration form
        form_frame = ttk.Frame(container)
        form_frame.pack(pady=20, fill=tk.X)
        
        ttk.Label(form_frame, text="Username", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=(10, 5))
        self.reg_username_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 11))
        self.reg_username_entry.grid(row=1, column=0, pady=(0, 10), ipady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Email", font=("Segoe UI", 10, "bold")).grid(
            row=2, column=0, sticky=tk.W, pady=(10, 5))
        self.email_entry = ttk.Entry(form_frame, width=30, font=("Segoe UI", 11))
        self.email_entry.grid(row=3, column=0, pady=(0, 10), ipady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Password", font=("Segoe UI", 10, "bold")).grid(
            row=4, column=0, sticky=tk.W, pady=(10, 5))
        self.reg_password_entry = ttk.Entry(form_frame, width=30, show="•", font=("Segoe UI", 11))
        self.reg_password_entry.grid(row=5, column=0, pady=(0, 10), ipady=5, sticky=tk.EW)
        
        ttk.Label(form_frame, text="Confirm Password", font=("Segoe UI", 10, "bold")).grid(
            row=6, column=0, sticky=tk.W, pady=(10, 5))
        self.confirm_password_entry = ttk.Entry(form_frame, width=30, show="•", font=("Segoe UI", 11))
        self.confirm_password_entry.grid(row=7, column=0, pady=(0, 20), ipady=5, sticky=tk.EW)
        
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
        
        # Configure column weight for responsive design
        form_frame.columnconfigure(0, weight=1)
        
        # Bind Enter key to register
        self.root.bind('<Return>', lambda e: self.handle_register())
        
        # Focus on username field
        self.reg_username_entry.focus()
    
    def show_loading_screen(self, provider):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main container
        container = ttk.Frame(self.root, padding=30)
        container.pack(fill=tk.BOTH, expand=True)
        
        # Loading animation
        loading_frame = ttk.Frame(container)
        loading_frame.pack(expand=True)
        
        ttk.Label(loading_frame, text=f"Connecting to {provider}...", 
                 font=("Segoe UI", 14), 
                 foreground=self.accent_color).pack(pady=20)
        
        # Simulated progress bar
        progress = ttk.Progressbar(loading_frame, mode='indeterminate', length=300)
        progress.pack(pady=10)
        progress.start(15)
        
        ttk.Label(loading_frame, text="Please wait while we authenticate you", 
                 font=("Segoe UI", 10), 
                 foreground=self.light_text).pack(pady=5)
        
        # Update the UI
        self.root.update()
    
    def handle_google_login(self):
        # Open browser for Google OAuth
        auth_url = self.oauth_manager.get_google_auth_url()
        webbrowser.open(auth_url)
        
        # Show loading screen
        self.show_loading_screen("Google")
        
        # In a real application, you would need to set up a local server
        # to handle the OAuth callback. For this example, we'll simulate
        # the process with a dialog to enter the authorization code
        self.ask_for_oauth_code("Google")
    
    def handle_github_login(self):
        # Open browser for GitHub OAuth
        auth_url = self.oauth_manager.get_github_auth_url()
        webbrowser.open(auth_url)
        
        # Show loading screen
        self.show_loading_screen("GitHub")
        
        # In a real application, you would need to set up a local server
        # to handle the OAuth callback. For this example, we'll simulate
        # the process with a dialog to enter the authorization code
        self.ask_for_oauth_code("GitHub")
    
    def ask_for_oauth_code(self, provider):
        # Create a dialog to enter the OAuth code
        dialog = tk.Toplevel(self.root)
        dialog.title(f"{provider} Authentication")
        dialog.geometry("400x200")
        dialog.configure(bg="#f5f7ff")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Please enter the authorization code from {provider}:", 
                 font=("Segoe UI", 10), padding=20).pack(pady=10)
        
        code_entry = ttk.Entry(dialog, width=40, font=("Segoe UI", 11))
        code_entry.pack(pady=10, padx=20, fill=tk.X)
        
        def submit_code():
            code = code_entry.get().strip()
            if code:
                dialog.destroy()
                self.process_oauth_code(provider, code)
            else:
                messagebox.showerror("Error", "Please enter an authorization code")
        
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Submit", command=submit_code).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side=tk.LEFT, padx=5)
        
        code_entry.focus()
    
    def process_oauth_code(self, provider, code):
        self.show_loading_screen(provider)
        
        try:
            if provider == "Google":
                access_token = self.oauth_manager.exchange_google_code(code)
                if access_token:
                    user_data = self.oauth_manager.get_google_user_info(access_token)
                else:
                    messagebox.showerror("Error", "Failed to authenticate with Google")
                    self.show_login_screen()
                    return
            else:  # GitHub
                access_token = self.oauth_manager.exchange_github_code(code)
                if access_token:
                    user_data = self.oauth_manager.get_github_user_info(access_token)
                else:
                    messagebox.showerror("Error", "Failed to authenticate with GitHub")
                    self.show_login_screen()
                    return
            
            if user_data:
                success, message = self.user_manager.oauth_login(user_data)
                if success:
                    messagebox.showinfo("Success", message)
                    self.show_todo_app()
                else:
                    messagebox.showerror("Error", message)
                    self.show_login_screen()
            else:
                messagebox.showerror("Error", "Failed to get user information")
                self.show_login_screen()
                
        except Exception as e:
            messagebox.showerror("Error", f"Authentication failed: {str(e)}")
            self.show_login_screen()
    
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
    
    def show_todo_app(self):
        # Clear the window
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Configure main window
        self.root.geometry("1000x700")
        
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
        
        user_data = self.user_manager.users[self.user_manager.current_user]
        provider = user_data.get('provider', 'email')
        
        ttk.Label(user_frame, text=f"Welcome, {self.user_manager.current_user}", 
                 font=("Segoe UI", 10), 
                 foreground=self.light_text).pack(side=tk.LEFT, padx=(0, 10))
        
        if provider != 'email':
            provider_text = f"({provider.capitalize()})"
            ttk.Label(user_frame, text=provider_text, 
                     font=("Segoe UI", 9), 
                     foreground=self.accent_color).pack(side=tk.LEFT, padx=(0, 10))
        
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
        self.task_entry.grid(row=0, column=1, padx=(0, 15), ipady=4, sticky=tk.EW)
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
        
        # Configure column weights for responsive design
        add_frame.columnconfigure(1, weight=1)
        
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