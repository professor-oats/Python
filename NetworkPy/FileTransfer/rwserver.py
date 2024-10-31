from flask import Flask, request, jsonify
import os

app = Flask(__name__)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload_file():
  if 'file' not in request.files:
    return jsonify({'message': 'No file part in the request'}), 400

  file = request.files['file']

  if file.filename == '':
    return jsonify({'message': 'No file selected'}), 400

  # Retrieve the relative path from the request form data
  relative_path = request.form.get('relative_path', file.filename)
  normalized_path = relative_path.replace('\\', '/')  # Convert Windows backslashes to Unix

  # Construct the full path by joining the UPLOAD_FOLDER with the normalized path
  full_path = os.path.join(UPLOAD_FOLDER, normalized_path)

  # Create any necessary subdirectories
  os.makedirs(os.path.dirname(full_path), exist_ok=True)

  file.save(full_path)
  return jsonify({'message': f'File {normalized_path} uploaded successfully'}), 200

if __name__ == '__main__':
  app.run(host='192.168.10.150', port=9999)
