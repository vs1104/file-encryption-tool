from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging
from datetime import datetime, timedelta
from mimetypes import guess_type
from encryption import generate_rsa_keys, encrypt_file, decrypt_file, batch_encrypt_files, batch_decrypt_files
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')

# Initialize rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

users = {
    1: User(1, "user1", generate_password_hash("password1")),
    2: User(2, "user2", generate_password_hash("password2"))
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(int(user_id))

logging.basicConfig(level=logging.DEBUG)

KEYS_FOLDER = os.path.join(os.path.dirname(__file__), "keys")
FILES_FOLDER = os.path.join(os.path.dirname(__file__), "files")

os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)

shareable_links = {}

def send_email_notification(subject, body, to_email):
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    sender_email = os.environ.get('SMTP_EMAIL', 'your_email@gmail.com')
    sender_password = os.environ.get('SMTP_PASSWORD', 'your_password')

    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, to_email, msg.as_string())
        logging.info("Email notification sent successfully!")
    except Exception as e:
        logging.error(f"Failed to send email notification: {e}")

def get_user_file_directory(user_id):
    user_dir = os.path.join(FILES_FOLDER, f"user_{user_id}")
    os.makedirs(user_dir, exist_ok=True)
    return user_dir

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {'pdf', 'doc', 'docx', 'txt', 'png', 'jpg', 'jpeg'}

def get_original_filename(filename):
    if filename.endswith('.enc'):
        return filename[:-4]
    return filename

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
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
        elif next((user for user in users.values() if user.username == username), None):
            flash("Username already exists.", "danger")
        else:
            user_id = max(users.keys()) + 1
            users[user_id] = User(user_id, username, generate_password_hash(password))
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/")
@login_required
def index():
    user_dir = get_user_file_directory(current_user.id)
    files = []
    for filename in os.listdir(user_dir):
        file_path = os.path.join(user_dir, filename)
        if os.path.isfile(file_path):
            files.append({
                'name': filename,
                'is_encrypted': filename.endswith('.enc'),
                'original_name': get_original_filename(filename),
                'size': os.path.getsize(file_path),
                'modified': datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M')
            })
    return render_template("index.html", files=files)

@app.route("/generate_keys", methods=["POST"])
@login_required
def generate_keys():
    try:
        private_key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
        public_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")
        if os.path.exists(private_key_path) or os.path.exists(public_key_path):
            flash("Keys already exist. Delete them first if you want to regenerate.", "warning")
        else:
            generate_rsa_keys(private_key_path, public_key_path)
            flash("Keys generated successfully!", "success")
    except Exception as e:
        logging.error(f"Error generating keys: {e}")
        flash("Failed to generate keys.", "danger")
    return redirect(url_for("index"))

@app.route("/encrypt", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def encrypt():
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file selected"}), 400
        
        files = request.files.getlist('file')
        if len(files) == 0 or files[0].filename == '':
            return jsonify({"status": "error", "message": "No files selected"}), 400
        
        password = request.form.get("password", "").strip()
        if not password:
            return jsonify({"status": "error", "message": "Password is required"}), 400
        
        public_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")
        if not os.path.exists(public_key_path):
            return jsonify({"status": "error", "message": "Public key not found"}), 400
        
        user_dir = get_user_file_directory(current_user.id)
        temp_files = []
        original_filenames = []
        
        # Validate all files first
        for file in files:
            if not allowed_file(file.filename):
                return jsonify({"status": "error", "message": f"File type not allowed: {file.filename}"}), 400
            
            original_filename = file.filename
            encrypted_filename = f"{original_filename}.enc"
            encrypted_path = os.path.join(user_dir, encrypted_filename)
            
            if os.path.exists(encrypted_path):
                return jsonify({"status": "error", "message": f"Encrypted file already exists: {encrypted_filename}"}), 400
            
            original_filenames.append(original_filename)
            temp_path = os.path.join(user_dir, f"temp_{original_filename}")
            temp_files.append(temp_path)
            file.save(temp_path)
        
        # Process batch encryption
        results = batch_encrypt_files(
            input_paths=temp_files,
            public_key_path=public_key_path,
            output_folder=user_dir,
            password=password
        )
        
        # Clean up temp files
        for temp_path in temp_files:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
        # Check results
        success_count = sum(1 for result in results if result['status'] == 'success')
        if success_count == 0:
            return jsonify({"status": "error", "message": "Failed to encrypt all files"}), 500
        
        # Send notification
        send_email_notification(
            subject="Files Encrypted",
            body=f"{success_count} file(s) have been encrypted successfully.",
            to_email="user@example.com"
        )
        
        return jsonify({
            "status": "success",
            "message": f"Successfully encrypted {success_count}/{len(files)} files",
            "results": results
        })
    except Exception as e:
        logging.error(f"Error encrypting files: {e}")
        # Clean up any remaining temp files
        for temp_path in temp_files:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        return jsonify({
            "status": "error",
            "message": f"Failed to encrypt files: {str(e)}"
        }), 500

@app.route("/decrypt", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def decrypt():
    try:
        if 'file' not in request.files:
            return jsonify({"status": "error", "message": "No file selected"}), 400
        
        files = request.files.getlist('file')
        if len(files) == 0 or files[0].filename == '':
            return jsonify({"status": "error", "message": "No files selected"}), 400
        
        password = request.form.get("password", "").strip()
        if not password:
            return jsonify({"status": "error", "message": "Password is required"}), 400
        
        private_key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
        if not os.path.exists(private_key_path):
            return jsonify({"status": "error", "message": "Private key not found"}), 400
        
        user_dir = get_user_file_directory(current_user.id)
        temp_files = []
        encrypted_filenames = []
        
        # Validate all files first
        for file in files:
            if not file.filename.endswith('.enc'):
                return jsonify({"status": "error", "message": f"File is not encrypted: {file.filename}"}), 400
            
            encrypted_filename = file.filename
            original_filename = get_original_filename(encrypted_filename)
            decrypted_path = os.path.join(user_dir, original_filename)
            
            if os.path.exists(decrypted_path):
                return jsonify({"status": "error", "message": f"Decrypted file already exists: {original_filename}"}), 400
            
            encrypted_filenames.append(encrypted_filename)
            temp_path = os.path.join(user_dir, f"temp_{encrypted_filename}")
            temp_files.append(temp_path)
            file.save(temp_path)
        
        # Process batch decryption
        results = batch_decrypt_files(
            input_paths=temp_files,
            private_key_path=private_key_path,
            output_folder=user_dir,
            password=password
        )
        
        # Clean up temp files
        for temp_path in temp_files:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        
        # Check results
        success_count = sum(1 for result in results if result['status'] == 'success')
        if success_count == 0:
            return jsonify({"status": "error", "message": "Failed to decrypt all files"}), 500
        
        # Send notification
        send_email_notification(
            subject="Files Decrypted",
            body=f"{success_count} file(s) have been decrypted successfully.",
            to_email="user@example.com"
        )
        
        return jsonify({
            "status": "success",
            "message": f"Successfully decrypted {success_count}/{len(files)} files",
            "results": results
        })
    except Exception as e:
        logging.error(f"Error decrypting files: {e}")
        # Clean up any remaining temp files
        for temp_path in temp_files:
            if os.path.exists(temp_path):
                os.remove(temp_path)
        return jsonify({
            "status": "error",
            "message": f"Failed to decrypt files: {str(e)}"
        }), 500

@app.route("/generate_shareable_link/<filename>", methods=["POST"])
@limiter.limit("10 per minute")
@login_required
def generate_shareable_link(filename):
    try:
        user_dir = get_user_file_directory(current_user.id)
        file_path = os.path.join(user_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({"error": "File not found"}), 404
            
        if not filename.endswith('.enc'):
            return jsonify({"error": "Only encrypted files can be shared"}), 400
            
        token = os.urandom(16).hex()
        expiration_time = datetime.now() + timedelta(hours=24)
        
        shareable_links[token] = {
            "user_id": current_user.id,
            "filename": filename,
            "expiration_time": expiration_time,
            "download_count": 0,
            "max_downloads": 5
        }
        
        shareable_url = url_for("download_shareable_file", token=token, _external=True)
        
        return jsonify({
            "status": "success",
            "link": shareable_url,
            "expires": expiration_time.strftime('%Y-%m-%d %H:%M'),
            "max_downloads": 5
        })
        
    except Exception as e:
        logging.error(f"Error generating shareable link: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/share/<token>")
def download_shareable_file(token):
    try:
        if token not in shareable_links:
            flash("Invalid or expired link", "danger")
            return redirect(url_for("index"))
        
        link_data = shareable_links[token]
        if datetime.now() > link_data["expiration_time"]:
            del shareable_links[token]
            flash("Link has expired", "danger")
            return redirect(url_for("index"))
            
        if link_data["download_count"] >= link_data["max_downloads"]:
            del shareable_links[token]
            flash("Maximum downloads reached for this link", "danger")
            return redirect(url_for("index"))
            
        user_dir = get_user_file_directory(link_data["user_id"])
        file_path = os.path.join(user_dir, link_data["filename"])
        
        if not os.path.exists(file_path):
            del shareable_links[token]
            flash("File no longer exists", "danger")
            return redirect(url_for("index"))
            
        shareable_links[token]["download_count"] += 1
        
        return send_from_directory(
            user_dir,
            link_data["filename"],
            as_attachment=True,
            download_name=link_data["filename"]
        )
        
    except Exception as e:
        logging.error(f"Error downloading shareable file: {str(e)}")
        flash("Failed to download file", "danger")
        return redirect(url_for("index"))

@app.route("/files/<filename>")
@login_required
def download_file(filename):
    user_dir = get_user_file_directory(current_user.id)
    file_path = os.path.join(user_dir, filename)
    
    if not os.path.exists(file_path):
        flash("File not found.", "danger")
        return redirect(url_for("index"))
    
    mime_types = {
        '.pdf': 'application/pdf',
        '.doc': 'application/msword',
        '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        '.txt': 'text/plain',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.enc': 'application/octet-stream'
    }
    
    extension = os.path.splitext(filename)[1].lower()
    mimetype = mime_types.get(extension, guess_type(filename)[0] or 'application/octet-stream')
    
    return send_from_directory(
        user_dir,
        filename,
        mimetype=mimetype,
        as_attachment=True,
        download_name=filename
    )

@app.route("/delete_file/<filename>", methods=["DELETE"])
@login_required
def delete_file(filename):
    try:
        user_dir = get_user_file_directory(current_user.id)
        file_path = os.path.join(user_dir, filename)
        
        if os.path.exists(file_path):
            os.remove(file_path)
            return jsonify({"status": "success", "message": "File deleted successfully"})
        return jsonify({"status": "error", "message": "File not found"}), 404
    except Exception as e:
        logging.error(f"Error deleting file: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5005)