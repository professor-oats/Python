import requests

def upload_file(file_path, server_url='http://192.168.1.150:9999/upload'):
    # Open the file in binary mode and upload it
    try:
        with open(file_path, 'rb') as file:
            # Send the file to the server
            files = {'file': file}
            response = requests.post(server_url, files=files)

        # Print the server's response
        print(f'File: {file_path}')
        print(f'Status Code: {response.status_code}')
        print(f'Response: {response.json()}')

    except FileNotFoundError:
        print(f'Error: File not found: {file_path}')
    except Exception as e:
        print(f'Error while uploading {file_path}: {e}')

def upload_files(file_paths, server_url='http://192.168.1.150:9999/upload'):
    for file_path in file_paths:
        upload_file(file_path, server_url)

if __name__ == '__main__':
    # List of files to be uploaded
    file_paths = [
        '/path/to/file',
        '/path/to/otherfile'
        # Add more file paths as needed
    ]
    
    # Upload all files
    upload_files(file_paths)