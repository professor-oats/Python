from flask import Flask, request, render_template_string, jsonify
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
MAX_UPLOAD_SIZE = 1024 * 1024 * 1024  # 1 GB

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_SIZE

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Upload ZIP</title>
</head>
<body>
    <h2>Upload ZIP Archive</h2>

    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".zip" required>
        <button type="submit">Upload</button>
    </form>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)

@app.route("/upload", methods=["POST"])
def upload_file():

    if "file" not in request.files:
        return jsonify({"message": "No file provided"}), 400

    file = request.files["file"]

    if file.filename == "":
        return jsonify({"message": "No file selected"}), 400

    # Yes, this is AI pasta, surprisingly it went with .zip. May fix later
    if not file.filename.lower().endswith(".zip"):
        return jsonify({"message": "Only ZIP files allowed"}), 400

    filename = secure_filename(file.filename)

    save_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(save_path)

    return jsonify({
        "message": "Upload successful",
        "filename": filename
    })

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=9999
    )


