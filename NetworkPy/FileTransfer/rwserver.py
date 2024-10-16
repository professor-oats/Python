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

  file.save(os.path.join(UPLOAD_FOLDER, file.filename))
  return jsonify({'message': f'File {file.filename} uploaded successfully'}), 200

if __name__ == '__main__':
  app.run(host='192.168.1.150', port=9999)
