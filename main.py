import gradio as gr
import requests
import json
from typing import Optional, Tuple
import subprocess
import time
import os
import signal

API_BASE_URL = "http://localhost:8001"

class AuthClient:
    def __init__(self):
        self.token = None
        self.username = None
    
    def register(self, username: str, email: str, password: str) -> Tuple[bool, str]:
        try:
            response = requests.post(
                f"{API_BASE_URL}/register",
                json={"username": username, "email": email, "password": password}
            )
            if response.status_code == 200:
                return True, f"Registration successful! User {username} created."
            else:
                return False, f"Registration failed: {response.json().get('detail', 'Unknown error')}"
        except requests.exceptions.ConnectionError:
            return False, "Cannot connect to server. Please ensure the API server is running."
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def login(self, username: str, password: str) -> Tuple[bool, str]:
        try:
            response = requests.post(
                f"{API_BASE_URL}/token",
                data={"username": username, "password": password}
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data["access_token"]
                self.username = username
                return True, f"Login successful! Welcome, {username}!"
            else:
                return False, "Login failed: Invalid credentials"
        except requests.exceptions.ConnectionError:
            return False, "Cannot connect to server. Please ensure the API server is running."
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def logout(self) -> Tuple[bool, str]:
        if not self.token:
            return False, "Not logged in"
        
        try:
            response = requests.post(
                f"{API_BASE_URL}/logout",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            self.token = None
            self.username = None
            return True, "Logged out successfully!"
        except Exception as e:
            self.token = None
            self.username = None
            return True, "Logged out (local)"
    
    def get_profile(self) -> Tuple[bool, str]:
        if not self.token:
            return False, "Please login first"
        
        try:
            response = requests.get(
                f"{API_BASE_URL}/users/me",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                data = response.json()
                profile_info = f"""
                **User Profile**
                - ID: {data['id']}
                - Username: {data['username']}
                - Email: {data['email']}
                - Active: {data['is_active']}
                - Created: {data['created_at']}
                - Last Login: {data.get('last_login', 'N/A')}
                """
                return True, profile_info
            else:
                return False, "Failed to get profile"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def change_password(self, current_password: str, new_password: str) -> Tuple[bool, str]:
        if not self.token:
            return False, "Please login first"
        
        try:
            response = requests.post(
                f"{API_BASE_URL}/users/me/change-password",
                json={"current_password": current_password, "new_password": new_password},
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                return True, "Password changed successfully!"
            else:
                return False, f"Failed to change password: {response.json().get('detail', 'Unknown error')}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def update_profile(self, username: Optional[str] = None, email: Optional[str] = None) -> Tuple[bool, str]:
        if not self.token:
            return False, "Please login first"
        
        update_data = {}
        if username:
            update_data["username"] = username
        if email:
            update_data["email"] = email
        
        if not update_data:
            return False, "No data to update"
        
        try:
            response = requests.put(
                f"{API_BASE_URL}/users/me",
                json=update_data,
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                if username:
                    self.username = username
                return True, "Profile updated successfully!"
            else:
                return False, f"Failed to update profile: {response.json().get('detail', 'Unknown error')}"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def delete_account(self) -> Tuple[bool, str]:
        if not self.token:
            return False, "Please login first"
        
        try:
            response = requests.delete(
                f"{API_BASE_URL}/users/me",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                self.token = None
                self.username = None
                return True, "Account deleted successfully!"
            else:
                return False, "Failed to delete account"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def deactivate_account(self) -> Tuple[bool, str]:
        if not self.token:
            return False, "Please login first"
        
        try:
            response = requests.post(
                f"{API_BASE_URL}/users/me/deactivate",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                return True, "Account deactivated successfully!"
            else:
                return False, "Failed to deactivate account"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def list_users(self) -> Tuple[bool, str]:
        if not self.token:
            return False, "Please login first"
        
        try:
            response = requests.get(
                f"{API_BASE_URL}/users",
                headers={"Authorization": f"Bearer {self.token}"}
            )
            if response.status_code == 200:
                users = response.json()
                if not users:
                    return True, "No users found"
                
                users_list = "**Registered Users:**\n\n"
                for user in users:
                    users_list += f"- {user['username']} ({user['email']}) - Active: {user['is_active']}\n"
                return True, users_list
            else:
                return False, "Failed to get users list"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def reset_password(self, email: str, new_password: str) -> Tuple[bool, str]:
        try:
            response = requests.post(
                f"{API_BASE_URL}/password-reset",
                json={"email": email, "new_password": new_password}
            )
            if response.status_code == 200:
                return True, "Password reset successfully!"
            else:
                return False, f"Failed to reset password: {response.json().get('detail', 'Unknown error')}"
        except Exception as e:
            return False, f"Error: {str(e)}"

auth_client = AuthClient()
server_process = None

def start_server():
    global server_process
    try:
        server_process = subprocess.Popen(
            ["uvicorn", "server:app", "--reload", "--host", "0.0.0.0", "--port", "8001"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(3)
        return "API Server started on http://localhost:8001"
    except Exception as e:
        return f"Failed to start server: {str(e)}"

def stop_server():
    global server_process
    if server_process:
        try:
            server_process.terminate()
            server_process.wait(timeout=5)
            server_process = None
            return "API Server stopped"
        except subprocess.TimeoutExpired:
            server_process.kill()
            server_process = None
            return "API Server force stopped"
    else:
        return "Server is not running"

def check_server_status():
    try:
        response = requests.get(f"{API_BASE_URL}/")
        if response.status_code == 200:
            return "✅ Server is running"
        else:
            return "⚠️ Server is responding but not healthy"
    except:
        return "❌ Server is not running"

def create_interface():
    with gr.Blocks(title="User Authentication System") as app:
        gr.Markdown("# 🔐 User Authentication System")
        gr.Markdown("Complete user management system with SQLite database")
        
        with gr.Tab("🏠 Home"):
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### Current Session")
                    session_status = gr.Textbox(
                        label="Status", 
                        value=f"Logged in as: {auth_client.username}" if auth_client.username else "Not logged in",
                        interactive=False
                    )
                    
                    with gr.Row():
                        profile_btn = gr.Button("View Profile", variant="primary")
                        refresh_btn = gr.Button("Refresh Status")
                    
                    profile_output = gr.Markdown()
                    
                    def update_session_status():
                        if auth_client.username:
                            return f"Logged in as: {auth_client.username}"
                        return "Not logged in"
                    
                    def view_profile():
                        success, message = auth_client.get_profile()
                        return message
                    
                    profile_btn.click(view_profile, outputs=profile_output)
                    refresh_btn.click(update_session_status, outputs=session_status)
                
                with gr.Column():
                    gr.Markdown("### Server Control")
                    server_status = gr.Textbox(label="Server Status", value=check_server_status(), interactive=False)
                    
                    with gr.Row():
                        start_btn = gr.Button("Start Server", variant="primary")
                        stop_btn = gr.Button("Stop Server", variant="stop")
                        check_btn = gr.Button("Check Status")
                    
                    server_output = gr.Textbox(label="Server Output", interactive=False)
                    
                    start_btn.click(start_server, outputs=server_output)
                    stop_btn.click(stop_server, outputs=server_output)
                    check_btn.click(check_server_status, outputs=server_status)
        
        with gr.Tab("📝 Register"):
            gr.Markdown("### Create a New Account")
            with gr.Row():
                with gr.Column():
                    reg_username = gr.Textbox(label="Username", placeholder="Enter username")
                    reg_email = gr.Textbox(label="Email", placeholder="Enter email")
                    reg_password = gr.Textbox(label="Password", type="password", placeholder="Enter password")
                    reg_button = gr.Button("Register", variant="primary")
                
                with gr.Column():
                    reg_output = gr.Textbox(label="Registration Result", interactive=False)
            
            def handle_register(username, email, password):
                if not username or not email or not password:
                    return "Please fill all fields"
                success, message = auth_client.register(username, email, password)
                return message
            
            reg_button.click(handle_register, inputs=[reg_username, reg_email, reg_password], outputs=reg_output)
        
        with gr.Tab("🔑 Login"):
            gr.Markdown("### Login to Your Account")
            with gr.Row():
                with gr.Column():
                    login_username = gr.Textbox(label="Username", placeholder="Enter username")
                    login_password = gr.Textbox(label="Password", type="password", placeholder="Enter password")
                    login_button = gr.Button("Login", variant="primary")
                    logout_button = gr.Button("Logout", variant="stop")
                
                with gr.Column():
                    login_output = gr.Textbox(label="Login Result", interactive=False)
            
            def handle_login(username, password):
                if not username or not password:
                    return "Please enter username and password"
                success, message = auth_client.login(username, password)
                return message
            
            def handle_logout():
                success, message = auth_client.logout()
                return message
            
            login_button.click(handle_login, inputs=[login_username, login_password], outputs=login_output)
            logout_button.click(handle_logout, outputs=login_output)
        
        with gr.Tab("🔐 Change Password"):
            gr.Markdown("### Change Your Password")
            with gr.Row():
                with gr.Column():
                    current_pwd = gr.Textbox(label="Current Password", type="password")
                    new_pwd = gr.Textbox(label="New Password", type="password")
                    confirm_pwd = gr.Textbox(label="Confirm New Password", type="password")
                    change_pwd_button = gr.Button("Change Password", variant="primary")
                
                with gr.Column():
                    pwd_output = gr.Textbox(label="Result", interactive=False)
            
            def handle_change_password(current, new, confirm):
                if not current or not new or not confirm:
                    return "Please fill all fields"
                if new != confirm:
                    return "New passwords don't match"
                success, message = auth_client.change_password(current, new)
                return message
            
            change_pwd_button.click(
                handle_change_password, 
                inputs=[current_pwd, new_pwd, confirm_pwd], 
                outputs=pwd_output
            )
        
        with gr.Tab("🔄 Reset Password"):
            gr.Markdown("### Reset Password (Forgot Password)")
            with gr.Row():
                with gr.Column():
                    reset_email = gr.Textbox(label="Email", placeholder="Enter your email")
                    reset_new_pwd = gr.Textbox(label="New Password", type="password")
                    reset_button = gr.Button("Reset Password", variant="primary")
                
                with gr.Column():
                    reset_output = gr.Textbox(label="Result", interactive=False)
            
            def handle_reset_password(email, new_password):
                if not email or not new_password:
                    return "Please fill all fields"
                success, message = auth_client.reset_password(email, new_password)
                return message
            
            reset_button.click(
                handle_reset_password,
                inputs=[reset_email, reset_new_pwd],
                outputs=reset_output
            )
        
        with gr.Tab("👤 Profile"):
            gr.Markdown("### Update Your Profile")
            with gr.Row():
                with gr.Column():
                    update_username = gr.Textbox(label="New Username (optional)", placeholder="Leave empty to keep current")
                    update_email = gr.Textbox(label="New Email (optional)", placeholder="Leave empty to keep current")
                    update_button = gr.Button("Update Profile", variant="primary")
                
                with gr.Column():
                    update_output = gr.Textbox(label="Update Result", interactive=False)
            
            def handle_update_profile(username, email):
                success, message = auth_client.update_profile(
                    username=username if username else None,
                    email=email if email else None
                )
                return message
            
            update_button.click(
                handle_update_profile,
                inputs=[update_username, update_email],
                outputs=update_output
            )
        
        with gr.Tab("👥 Users"):
            gr.Markdown("### View All Users")
            list_button = gr.Button("List All Users", variant="primary")
            users_output = gr.Markdown()
            
            def handle_list_users():
                success, message = auth_client.list_users()
                return message
            
            list_button.click(handle_list_users, outputs=users_output)
        
        with gr.Tab("⚠️ Account"):
            gr.Markdown("### Account Management")
            gr.Markdown("⚠️ **Warning**: These actions cannot be undone!")
            
            with gr.Row():
                with gr.Column():
                    deactivate_button = gr.Button("Deactivate Account", variant="secondary")
                    delete_button = gr.Button("Delete Account", variant="stop")
                
                with gr.Column():
                    account_output = gr.Textbox(label="Result", interactive=False)
            
            def handle_deactivate():
                success, message = auth_client.deactivate_account()
                return message
            
            def handle_delete():
                success, message = auth_client.delete_account()
                return message
            
            deactivate_button.click(handle_deactivate, outputs=account_output)
            delete_button.click(handle_delete, outputs=account_output)
    
    return app

if __name__ == "__main__":
    print("Starting User Authentication System...")
    print("Note: Make sure to start the API server first!")
    print("You can start the server from the Home tab in the interface.")
    
    app = create_interface()
    
    try:
        app.launch(
            server_name="0.0.0.0",
            server_port=7860,
            share=False,
            inbrowser=True
        )
    finally:
        if server_process:
            print("\nStopping API server...")
            stop_server()
