from http.server import HTTPServer, BaseHTTPRequestHandler
import ssl


httpd = HTTPServer(('localhost', 4443), BaseHTTPRequestHandler)

httpd.socket = ssl.wrap_socket (httpd.socket, 
        keyfile="src/ca/localhost.key", 
        certfile='src/ca/localhost.crt', server_side=True)

httpd.serve_forever()
