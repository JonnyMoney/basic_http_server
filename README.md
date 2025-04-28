# Simple HTTP Server with File Upload Support

This is a basic HTTP server implementation written in Python, designed to handle HTTP requests, including GET, HEAD, and POST methods. It supports file upload via the POST method, where users can upload files to a specified directory on the server.

## Features

- **GET & HEAD requests**: Retrieves files from the server and responds with appropriate HTTP headers.
- **POST requests**: Handles file uploads and saves them to a designated directory on the server.
- **Custom Redirection**: Supports URL redirection based on predefined rules.
- **Multipart form data parsing**: Parses multipart form data for file uploads.

# Run the server:
```bash
python basic_http_server.py
