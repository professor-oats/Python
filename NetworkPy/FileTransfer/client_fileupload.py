import requests
import os

def upload_file(file_path, relative_path, server_url='http://192.168.10.150:9999/upload'):  # /upload is the specified api route requested at flask server
    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            # Send the relative path as form data along with the file
            data = {'relative_path': relative_path}
            response = requests.post(server_url, files=files, data=data)

        # Print the server's response
        print(f'File: {relative_path}')
        print(f'Status Code: {response.status_code}')
        print(f'Response: {response.json()}')

    except FileNotFoundError:
        print(f'Error: File not found: {file_path}')
    except Exception as e:
        print(f'Error while uploading {file_path}: {e}')

def upload_directory(directory_path, server_url='http://192.168.10.150:9999/upload'):
    # Traverse the directory and its subdirectories
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            file_path = os.path.join(root, file)
            # Calculate the relative path for each file
            relative_path = os.path.relpath(file_path, start=directory_path)
            upload_file(file_path, relative_path, server_url)

if __name__ == '__main__':
    # Specify the directory you want to upload
    directory_path = 'C:/Users/chron/Documents/Programming/Python/ITHS/Project1'
    
    # Upload all files in the directory and subdirectories
    upload_directory(directory_path)