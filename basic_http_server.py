import socket
import mimetypes
import os
import re
from typing import Optional


IP = '127.0.0.1'
PORT = 8080

UPLOAD_PATH = "webroot/uploads"
DEFAULT_URL = "/index.html"

redirection_dictionary = {
    "/" : DEFAULT_URL
}


def handle_get_or_head(url: str, ver: str, headers: list[str], body: str, client_sock: socket.socket) -> tuple[bytes, bytes]:
    """Helper function for the GET or HEAD requests, processes file retrieval, and generates HTTP response."""
    if url in list(redirection_dictionary.keys()):
        url = redirection_dictionary[url]
    
    status_code = "200 OK"
    file_data = b''
    try:
        file_data = get_file_data(url)
    except FileNotFoundError as e:
        print(f"File Not found, returned 404")
        status_code = "404 Not Found"
    print(f"URL: [{url}]")
    file_type = mimetypes.guess_type(url)[0]
    resp = create_http_response(status_code, file_type, len(file_data))
    return resp, file_data
    
    

def handle_get(url: str, ver: str, headers: list[str], body: str, client_sock: socket.socket) -> bytes:
    """Handles GET requests by retrieving file data and returning the full HTTP response with body."""
    resp, file_data = handle_get_or_head(url, ver, headers, body, client_sock)
    resp += file_data

    return resp
    


def handle_head(url: str, ver: str, headers: list[str], body: str, client_sock: socket.socket) -> bytes:
    """Handles HEAD requests by generating the HTTP response header without the file body."""
    resp, file_data = handle_get_or_head(url, ver, headers, body, client_sock)
    return resp


def handle_post(url: str, ver: str, headers: list[str], body: bytes, client_sock: socket.socket) -> bytes:
    """Handles POST requests, processes file upload, and returns an HTTP response for the result."""
    body = ensure_full_body(client_sock, body, headers)

    boundary = get_boundary(headers)
    if not boundary:
        print("Missing boundary in Content-Type")
        return bad_request_response("Bad Request: Missing boundary")

    body_bytes = body  # don't decode to string
    filename, file_content = parse_body(body_bytes, boundary)

    if filename and file_content:
        save_uploaded_file(filename, file_content)
        response_text = f"File uploaded successfully as {filename}"
        return create_http_response("200 OK", "text/plain", len(response_text)) + response_text.encode()
    
    print("No file found in POST body")
    return bad_request_response("Bad Request: No file uploaded")


def ensure_full_body(client_sock: socket.socket, body: bytes, headers: list[str]) -> bytes:
    """Ensures the full body is received from the client based on the Content-Length header."""
    content_length = get_content_length(headers)
    if len(body) < content_length:
        body += recv_body(client_sock, content_length - len(body))
    return body


def get_content_length(headers: list[str]) -> int:
    """Extracts the content length from the headers for POST requests."""
    for header in headers:
        if header.lower().startswith("content-length:"):
            return int(header.split(":")[1].strip())
    return 0

def get_boundary(headers: list[str]) -> Optional[str]:
    """Extracts the boundary from the Content-Type header for multipart POST requests."""
    for header in headers:
        if header.lower().startswith("content-type:") and "boundary=" in header:
            return "--" + header.split("boundary=")[1].strip()
    return None


def bad_request_response(message: str) -> bytes:
    """Creates an HTTP 400 Bad Request response with the provided error message."""
    return create_http_response("400 Bad Request", "text/plain", len(message)) + message.encode()


def parse_body(body: bytes, boundary: str) -> tuple[Optional[str], Optional[bytes]]:
    """Parses the multipart form data and returns the filename and content of the uploaded file."""
    boundary_bytes = boundary.encode()
    parts = body.split(boundary_bytes)
    for part in parts:
        if b"Content-Disposition:" in part and b"filename=" in part:
            header, file_content = part.split(b"\r\n\r\n", 1)
            match = re.search(r'filename="(.+?)"', header.decode())
            if match:
                filename = match.group(1)
            else:
                filename = "uploaded_file.txt"
            file_content = file_content.rsplit(b"\r\n", 1)[0]
            return filename, file_content
    return None, None


def save_uploaded_file(filename: str, content: bytes):
    """Saves the uploaded file to the specified path on the server."""
    os.makedirs(UPLOAD_PATH, exist_ok=True)
    file_path = os.path.join(UPLOAD_PATH, filename)
    with open(file_path, "wb") as f:
        f.write(content)
    print(f"Saved file: {file_path}")
    

def handle_unsupported(url: str, ver: str, headers: list[str], body: str, client_sock: socket.socket) -> str:
    """Handles unsupported HTTP methods and returns a 405 Method Not Allowed response."""
    resp = create_http_response("405 Method Not Allowed", None, 0)
    return resp


handle_method = {
    "GET" : handle_get,
    "HEAD" : handle_head,
    "POST" : handle_post,
    "unsupported" : handle_unsupported
}


def create_http_response(status_code: str, file_type: Optional[str], file_len: int, version: str = "HTTP/1.1") -> bytes:
    """Generates an HTTP response header with status code, content type, and content length."""
    response = f"{version} {status_code}\r\n"
    if file_type:
        response += f"Content-Type: {file_type}\r\n"
    response += f"Content-Length: {file_len}\r\n\r\n"
    return response.encode()


def get_file_data(filename: str) -> bytes:
    """Retrieves the file content from the server's file system for the specified file."""
    file_data = b''
    with open(fr"webroot{filename}", 'rb') as file:
        file_data += file.read()

    return file_data

def handle_client(client_sock: socket.socket):
    """Handles an individual client request, parses the data, and sends the appropriate response."""
    request_data = recv_data(client_sock)

    # split into headers and body
    header_end_idx = request_data.find(b'\r\n\r\n')
    if header_end_idx == -1:
        client_sock.close()
        return

    headers_part = request_data[:header_end_idx].decode()
    body_part = request_data[header_end_idx + 4:]  # raw bytes

    try:
        method, url, ver, headers, body = parse_http_headers(headers_part, body_part)
    except ValueError as e:
        client_sock.close()
        return

    if method not in handle_method:
        print(f"unsupported method: [{method}]")
        method = "unsupported"

    resp = handle_method[method](url, ver, headers, body, client_sock)

    client_sock.send(resp)



def parse_http_headers(headers_text: str, body: bytes) -> tuple[str, str, str, list[str], bytes]:
    """Parses the HTTP request headers and body and returns the method, URL, version, headers, and body."""
    splitted_data = headers_text.split('\r\n')
    if len(splitted_data) < 2:
        raise ValueError("Invalid request format")

    first_line = splitted_data[0].split()
    if len(first_line) != 3:
        raise ValueError("First line must contain method, URL, and version")

    method, url, version = first_line
    headers = splitted_data[1:]

    return method, url, version, headers, body



def recv_data(client_sock: socket.socket) -> bytes:
    """Receives the full HTTP request data from the client socket."""
    data = b''
    while b'\r\n\r\n' not in data:
        packet = client_sock.recv(1024)
        if not packet:
            break
        data += packet
    return data

def recv_body(client_sock: socket.socket, content_length: int) -> bytes:
    """Receives the body content from the client socket based on the content length."""
    data = b''
    while len(data) < content_length:
        packet = client_sock.recv(content_length - len(data))
        if not packet:
            break
        data += packet
    return data

def create_server() -> socket.socket:
    """Creates and returns a server socket ready to accept client connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    return server_socket


def main():
    server_sock = create_server()
    server_sock.listen()
    print("listening for clients")
    while True:
        client_socket, client_address = server_sock.accept()
        print(f'recved connection at {client_address}')
        handle_client(client_socket)

        


if __name__ == "__main__":
    main()