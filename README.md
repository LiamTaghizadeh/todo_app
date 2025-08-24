# Modern Todo App with OAuth Authentication

A modern, feature-rich Todo application built with Python and Tkinter, featuring OAuth authentication with Google and GitHub.

![Todo App Screenshot](https://via.placeholder.com/800x400/5b6bf0/ffffff?text=Modern+Todo+App+with+OAuth)

## Features

### 🔐 Authentication
  - **Traditional Email/Password**: Register and login with email and password
  - **Google OAuth**: Sign in with your Google account
  - **GitHub OAuth**: Sign in with your GitHub account
  - **Secure Password Hashing**: Passwords are hashed using SHA-256
  - **Session Management**: Automatic login persistence

### ✅ Todo Management
  - **Add Tasks**: Create new tasks with priority levels (High, Medium, Low)
  - **Mark Complete**: Check off completed tasks
  - **Delete Tasks**: Remove individual tasks
  - **Clear Completed**: Remove all completed tasks at once
  - **Priority System**: Color-coded priorities for better organization
  - **Persistent Storage**: Todos are saved per user and persist between sessions

### 🎨 Modern UI/UX
  - **Clean Design**: Modern interface with thoughtful spacing and typography
  - **Responsive Layout**: Adapts to different window sizes
  - **Color Coding**: Visual priority indicators (red=high, orange=medium, green=low)
  - **Loading Screens**: Professional loading indicators for OAuth flows
  - **Intuitive Navigation**: Easy-to-use interface with clear feedback

## Installation

### Prerequisites
  - Python 3.7 or higher
  - pip (Python package manager)

### Steps
1. Clone the repository:
  ```bash
  git clone https://github.com/yourusername/modern-todo-app.git
  cd modern-todo-app
  ```

2. Install required dependencies:
  ```bash
  pip install requests
  ```

3. Set up OAuth credentials (see Configuration section below)

4. Run the application:
  ```bash
  python todo_app.py
  ```

## Configuration

### Google OAuth Setup
  1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
  2. Create a new project or select an existing one
  3. Enable the Google+ API
  4. Create OAuth 2.0 credentials (Web application type)
  5. Add `http://localhost:8080/google-callback` as an authorized redirect URI
  6. Replace the placeholder values in the code:
     - `YOUR_GOOGLE_CLIENT_ID` with your actual Client ID
     - `YOUR_GOOGLE_CLIENT_SECRET` with your actual Client Secret

### GitHub OAuth Setup
  1. Go to your GitHub [Developer Settings](https://github.com/settings/developers)
  2. Click "New OAuth App"
  3. Set Application name to "Modern Todo App"
  4. Set Homepage URL to `http://localhost:8080`
  5. Set Authorization callback URL to `http://localhost:8080/github-callback`
  6. Replace the placeholder values in the code:
     - `YOUR_GITHUB_CLIENT_ID` with your actual Client ID
     - `YOUR_GITHUB_CLIENT_SECRET` with your actual Client Secret

## Usage

### Signing Up
1. **Traditional Registration**: 
     - Click "Sign up" on the login screen
     - Fill in username, email, and password
     - Confirm your password and click "Create Account"

2. **OAuth Registration**:
     - Click "Sign up with Google" or "Sign up with GitHub"
     - You'll be redirected to the provider's authentication page
     - After authenticating, you'll be automatically registered

### Managing Todos
1. **Adding a Task**:
     - Type your task in the input field
     - Select a priority level (High, Medium, Low)
     - Press Enter or click "Add Task"

2. **Completing a Task**:
     - Select a task from the list
     - Click "Mark Complete" to check it off

3. **Deleting a Task**:
     - Select a task from the list
     - Click "Delete Task" to remove it

4. **Clearing Completed Tasks**:
     - Click "Clear Completed" to remove all checked tasks

## File Structure

```
modern-todo-app/
│
├── app2.py          # use web 2 tech
├── app.py           # use web 1 tech
├── users.json           # User database (auto-generated)
├── todos_username.json  # User-specific todo files (auto-generated)
├── README.md           # This file
└── requirements.txt    # Python dependencies
```

## Data Storage

  - **User Data**: Stored in `users.json` with hashed passwords
  - **Todo Data**: Each user has their own todo file (`todos_username.json`)
  - **OAuth Users**: Users registered via OAuth are stored without passwords

## Security Features

  - Password hashing with SHA-256
  - Input validation and sanitization
  - CSRF protection with state parameters in OAuth flow
  - Separate data storage per user
  - Secure OAuth token handling

## Contributing

  1. Fork the repository
  2. Create a feature branch (`git checkout -b feature/amazing-feature`)
  3. Commit your changes (`git commit -m 'Add some amazing feature'`)
  4. Push to the branch (`git push origin feature/amazing-feature`)
  5. Open a Pull Request

## Troubleshooting

### Common Issues

1. **OAuth not working**:
   - Ensure you've configured the OAuth credentials correctly
   - Check that redirect URIs match exactly

2. **Module not found errors**:
   - Make sure you've installed all required dependencies: `pip install requests`

3. **Authentication failures**:
   - Check your internet connection for OAuth flows
   - Verify your credentials are correctly set up

### Getting Help

If you encounter issues:
  1. Check the troubleshooting section above
  2. Search existing GitHub issues
  3. Create a new issue with details about your problem

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments
  
  - Google and GitHub for their OAuth APIs
  - Python and Tkinter communities for excellent documentation
  - Contributors who help improve this project

## Future Enhancements

  - [ ] Task categories and tags
  - [ ] Due dates and reminders
  - [ ] Task sharing between users
  - [ ] Data export functionality
  - [ ] Mobile app version
  - [ ] Dark mode theme
  - [ ] Keyboard shortcuts
  - [ ] Task search and filtering

---

