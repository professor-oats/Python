## When posting use command
## curl -X POST "file=@/path/to/file" http://192.168.10.150:8080
## Adjust for your machines IP and port

from http.server import BaseHTTPRequestHandler, HTTPServer
import cgi

class FileUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_type, pdict = cgi.parse_header(self.headers['Content-Type'])
        if content_type == 'multipart/form-data':
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={
                'REQUEST_METHOD': 'POST',
                'CONTENT_TYPE': self.headers['Content-Type']
            })
            if 'file' in form:
                file_item = form['file']
                with open("uploaded_file", "wb") as f:
                    f.write(file_item.file.read())
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"File received successfully")
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"No file part in the request")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid content type")
            
if __name__ == "__main__":
    server_address = ("192.168.10.150", 8080)  # Use your desired IP and port
    httpd = HTTPServer(server_address, FileUploadHandler)
    print("Listening on 192.168.10.150:8080")
    httpd.serve_forever()
