from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
import os
import logging
from datetime import datetime, timedelta
from mimetypes import guess_type
from encryption import generate_rsa_keys, encrypt_file, decrypt_file

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Required for flashing messages

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

@app.route("/")
def index():
    files = os.listdir(FILES_FOLDER)  # List files in the FILES_FOLDER directory
    logging.info(f"Files in FILES_FOLDER: {files}")  # Log the files
    return render_template("index.html", files=files)

@app.route("/generate_keys", methods=["POST"])
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
        output_path = os.path.join(FILES_FOLDER, file.filename + ".enc")
        
        file.save(output_path)  # Save the uploaded file temporarily
        encrypt_file(output_path, public_key_path, output_path, password)  # Encrypt the file
        flash("File encrypted successfully!", "success")
    except Exception as e:
        logging.error(f"Error encrypting file: {e}")
        flash("Failed to encrypt file.", "danger")
    return redirect(url_for("index"))  # Refresh the page

@app.route("/decrypt", methods=["POST"])
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
        output_path = os.path.join(FILES_FOLDER, file.filename.replace(".enc", ""))
        
        file.save(output_path)  # Save the uploaded file temporarily
        decrypt_file(output_path, private_key_path, output_path, password)  # Decrypt the file
        flash("File decrypted successfully!", "success")
    except Exception as e:
        logging.error(f"Error decrypting file: {e}")
        flash("Failed to decrypt file.", "danger")
    return redirect(url_for("index"))  # Refresh the page

@app.route("/files/<filename>")
def download_file(filename):
    # Guess the MIME type based on the file extension
    mimetype, _ = guess_type(filename)
    return send_from_directory(FILES_FOLDER, filename, mimetype=mimetype)

@app.route("/delete_file/<filename>", methods=["DELETE"])
def delete_file(filename):
    try:
        file_path = os.path.join(FILES_FOLDER, filename)
        os.remove(file_path)
        return "", 200
    except Exception as e:
        logging.error(f"Error deleting file: {e}")
        return "", 500

@app.route("/generate_shareable_link/<filename>", methods=["POST"])
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