from flask import Flask, render_template, request, redirect, url_for, send_from_directory
import os
from encryption import generate_rsa_keys, encrypt_file, decrypt_file

app = Flask(__name__)

# Folder paths
KEYS_FOLDER = os.path.join(os.path.dirname(__file__), "..", "keys")
FILES_FOLDER = os.path.join(os.path.dirname(__file__), "..", "files")

# Ensure folders exist
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(FILES_FOLDER, exist_ok=True)

@app.route("/")
def index():
    # Pass the 'os' module to the template
    return render_template("index.html", os=os)

@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    private_key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
    public_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")
    generate_rsa_keys(private_key_path, public_key_path)
    return redirect(url_for("index"))

@app.route("/encrypt", methods=["POST"])
def encrypt():
    file = request.files["file"]
    public_key_path = os.path.join(KEYS_FOLDER, "public_key.pem")
    output_path = os.path.join(FILES_FOLDER, file.filename + ".enc")
    
    file.save(output_path)
    encrypt_file(output_path, public_key_path, output_path)
    return redirect(url_for("index"))

@app.route("/decrypt", methods=["POST"])
def decrypt():
    file = request.files["file"]
    private_key_path = os.path.join(KEYS_FOLDER, "private_key.pem")
    output_path = os.path.join(FILES_FOLDER, file.filename.replace(".enc", ""))
    
    file.save(output_path)
    decrypt_file(output_path, private_key_path, output_path)
    return redirect(url_for("index"))

@app.route("/files/<filename>")
def download_file(filename):
    return send_from_directory(FILES_FOLDER, filename)

if __name__ == "__main__":
    app.run(debug=True, port=5003)  # Change the port here