from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import logging
from datetime import datetime, timedelta
from mimetypes import guess_type
from encryption import generate_rsa_keys, encrypt_file, decrypt_file
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for flashing messages

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# Mock user database (replace with a real database in production)
users = {
    1: User(1, "user1", generate_password_hash("password1")),
    2: User(2, "user2", generate_password_hash("password2"))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Folder paths
KEYS_FOLDER = os.path.join(os.path.dirname(__file__), "keys")
FILES_FOLDER = os.path.join(os.path.dirname(__file__), "files")

# Ensure folders exist
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)

# Dictionary to store shareable links and their expiration times
shareable_links = {}

# Function to send email notifications
def send_email_notification(subject, body, to_email):
    # Email configuration
    smtp_server = "smtp.gmail.com"  # Replace with your SMTP server
    smtp_port = 587  # Replace with your SMTP port
    sender_email = "your_email@gmail.com"  # Replace with your email
    sender_password = "your_password"  # Replace with your email password

    # Create the email
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    # Send the email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()  # Secure the connection
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        logging.info("Email notification sent successfully!")
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")

# Function to get user-specific file directory
def get_user_file_directory(user_id):
    user_dir = os.path.join(FILES_FOLDER, f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

# Routes for user authentication
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = next((user for user in users.values() if user.username == username), None)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if next((user for user in users.values() if user.username == username), None):
            flash("Username already exists.", "danger")
        else:
            user_id = max(users.keys()) + 1
            users[user_id] = User(user_id, username, generate_password_hash(password))
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

# Main routes
@app.route("/")
@login_required
def index():
    user_dir = get_user_file_directory(current_user.id)
    files = os.listdir(user_dir)  # List files in the user's directory
    logging.info(f"Files in user directory: {files}")  # Log the files
    return render_template("index.html", files=files)

@app.route("/generate_keys", methods=["POST"])
@login_required
def generate_keys():
    try:
        private_key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
        public_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")
        generate_rsa_keys(private_key_path, public_key_path)
        flash("Keys generated successfully!", "success")
    except Exception as e:
        logging.error(f"Error generating keys: {e}")
        flash("Failed to generate keys.", "danger")
    return redirect(url_for("index"))

@app.route("/encrypt", methods=["POST"])
@login_required
def encrypt():
    try:
        if "file" not in request.files:
            flash("No file selected.", "danger")
            return redirect(url_for("index"))
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("index"))
        
        password = request.form.get("password")
        public_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")
        user_dir = get_user_file_directory(current_user.id)
        output_path = os.path.join(user_dir, file.filename + ".enc")
        
        file.save(output_path)  # Save the uploaded file temporarily
        encrypt_file(output_path, public_key_path, output_path, password)  # Encrypt the file
        flash("File encrypted successfully!", "success")

        # Send email notification
        send_email_notification(
            subject="Encryption Complete",
            body=f"The file {file.filename} has been encrypted.",
            to_email="user@example.com"  # Replace with the user's email
        )

        # Return JSON response for desktop notification
        return jsonify({
            "status": "success",
            "message": "File encrypted successfully!",
            "notification": {
                "title": "Encryption Complete",
                "body": "Your file has been successfully encrypted."
            }
        })
    except Exception as e:
        logging.error(f"Error encrypting file: {e}")
        flash("Failed to encrypt file.", "danger")
        return jsonify({
            "status": "error",
            "message": "Failed to encrypt file."
        }), 500

@app.route("/decrypt", methods=["POST"])
@login_required
def decrypt():
    try:
        if "file" not in request.files:
            flash("No file selected.", "danger")
            return redirect(url_for("index"))
        
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.", "danger")
            return redirect(url_for("index"))
        
        password = request.form.get("password")
        private_key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
        user_dir = get_user_file_directory(current_user.id)
        
        # Extract the original file name (remove .enc extension)
        original_filename = file.filename.replace(".enc", "")
        output_path = os.path.join(user_dir, original_filename)
        
        file.save(output_path)  # Save the uploaded file temporarily
        decrypt_file(output_path, private_key_path, output_path, password)  # Decrypt the file
        flash("File decrypted successfully!", "success")

        # Send email notification
        send_email_notification(
            subject="Decryption Complete",
            body=f"The file {original_filename} has been decrypted.",
            to_email="user@example.com"  # Replace with the user's email
        )

        # Return JSON response for desktop notification
        return jsonify({
            "status": "success",
            "message": "File decrypted successfully!",
            "notification": {
                "title": "Decryption Complete",
                "body": "Your file has been successfully decrypted."
            }
        })
    except Exception as e:
        logging.error(f"Error decrypting file: {e}")
        flash("Failed to decrypt file.", "danger")
        return jsonify({
            "status": "error",
            "message": "Failed to decrypt file."
        }), 500

@app.route("/files/<filename>")
@login_required
def download_file(filename):
    user_dir = get_user_file_directory(current_user.id)
    file_path = os.path.join(user_dir, filename)
    if not os.path.exists(file_path):
        flash("File not found.", "danger")
        return redirect(url_for("index"))
    
    # Guess the MIME type based on the file extension
    mimetype, _ = guess_type(filename)
    return send_from_directory(user_dir, filename, mimetype=mimetype, as_attachment=True)

@app.route("/delete_file/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    try:
        user_dir = get_user_file_directory(current_user.id)
        file_path = os.path.join(user_dir, filename)
        os.remove(file_path)
        return "", 200
    except Exception as e:
        logging.error(f"Error deleting file: {e}")
        return "", 500

@app.route("/generate_shareable_link/<filename>", methods=["POST"])
@login_required
def generate_shareable_link(filename):
    try:
        # Generate a unique token for the file
        token = os.urandom(16).hex()
        
        # Set expiration time (e.g., 24 hours from now)
        expiration_time = datetime.now() + timedelta(hours=24)
        
        # Store the token and expiration time in the dictionary
        shareable_links[token] = {
            "filename": filename,
            "expiration_time": expiration_time
        }
        
        # Generate the shareable link
        shareable_link = url_for("download_shareable_file", token=token, _external=True)
        
        # Return the shareable link as a JSON response
        return jsonify({"link": shareable_link}), 200
    except Exception as e:
        logging.error(f"Error generating shareable link: {e}")
        return jsonify({"error": "Failed to generate shareable link."}), 500

@app.route("/download_shareable_file/<token>")
def download_shareable_file(token):
    try:
        # Check if the token exists and is not expired
        if token not in shareable_links:
            flash("Invalid or expired link.", "danger")
            return redirect(url_for("index"))
        
        link_data = shareable_links[token]
        if datetime.now() > link_data["expiration_time"]:
            # Delete the file and the link if expired
            file_path = os.path.join(FILES_FOLDER, link_data["filename"])
            if os.path.exists(file_path):
                os.remove(file_path)
            del shareable_links[token]
            flash("Link has expired and the file has been deleted.", "danger")
            return redirect(url_for("index"))
        
        # Serve the file
        return send_from_directory(FILES_FOLDER, link_data["filename"])
    except Exception as e:
        logging.error(f"Error downloading shareable file: {e}")
        flash("Failed to download file.", "danger")
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True, port=5005)