---
title: "Customizing Python's SimpleHTTPServer"
date: 2020-11-15T20:57:46-08:00
draft: false
toc: true
comments: true
twitterImage: 04.png
categories:
- python
---

The other day I customized the Python built-in SimpleHTTPServer with some
routes. I did not find a lot of info about it (most use it to serve files). This
is how I did some basic customization.

<!--more-->

This is for Python 3.8.6 (which what I have in my testing VM) but it should work
on Python 3.9 (and probably the same for Python 2).

Code is at
https://github.com/parsiya/Parsia-Code/tree/master/python-simplehttpserver.

# How to Serve Files
`python -m http.server 8080 --bind 127.0.0.1`.

# Custom GET Responses
But I needed to customize the path. Let's start with a simple implementation. We
need to create our own [BaseHTTPRequestHandler][handler-doc].

[handler-doc]: https://docs.python.org/3.8/library/http.server.html

```python
from http.server import HTTPServer, BaseHTTPRequestHandler

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        pass

httpd = HTTPServer(('localhost', 10000), MyHandler)
httpd.serve_forever()
```

To respond to GET requests we need to add code to `do_GET`. Let's say we want to
return a 200 response that says `It works!`.

```python
# 01.py
def do_GET(self):
    # send 200 response
    self.send_response(200)
    # send response headers
    self.end_headers()
    # send the body of the response
    self.wfile.write(bytes("01.py", "utf-8"))
```

{{< imgcap title="01.py" src="01.png" >}}

# Custom Response Headers
Note the server adds some default headers. To modify these we can use
[send_header][send_header] before calling [end_headers][end_headers]. This is
very useful for adding the `Content-Type` header.

[send_header]: https://docs.python.org/3.8/library/http.server.html#http.server.BaseHTTPRequestHandler.send_header
[end_headers]: https://docs.python.org/3.8/library/http.server.html#http.server.BaseHTTPRequestHandler.end_headers

```python
# 02.py
def do_GET(self):
    # send 200 response
    self.send_response(200)
    # add our own custom header
    self.send_header("myheader", "myvalue")
    # send response headers
    self.end_headers()
    # send the body of the response
    self.wfile.write(bytes("It Works!", "utf-8"))
```

{{< imgcap title="02.py" src="02.png" >}}

To override a header we cannot use `send_header` because it will just add it as
a new header to the response. Based on the documentation it seems like the
`Date` and `Server` response headers cannot be changed :(.

# Read Request Path and Query Strings
The complete path and query strings are in the `self.path` object inside
`do_GET` and similar methods. First we need to parse it with
[urllib.parse.urlparse][urlparse]. Then we can get the query string and path
from the parsed object's fields `query` and `path`, respectively.

```py
from urllib.parse import urlparse

def do_GET(self):
    # first we need to parse it
    parsed = urlparse(self.path)
    # get the query string
    query_string = parsed.query
    # get the request path, this new path does not have the query string
    path = parsed.path
```

[urlparse]: https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlparse

# Read Request Headers
I needed to read the incoming request headers. These are stored in the
[headers][headers] object. It is of type `http.client.HTTPMessage` which is a
subclass of [email.message.Message][message].

[headers]: https://docs.python.org/3.8/library/http.server.html#http.server.BaseHTTPRequestHandler.headers
[message]: https://docs.python.org/3/library/email.compat32-message.html#email.message.Message

We can get the first value of a header by name with `headers.get("header name")`
. To get all values for a specific header (because headers can be repeated) use
`headers.get_all("header name")`.

```python
# 03.py
def do_GET(self):
    # get the value of the "Authorization" header and echo it.
    authz = self.headers.get("authorization")
    # send 200 response
    self.send_response(200)
    # send response headers
    self.end_headers()
    # send the body of the response
    self.wfile.write(bytes(authz, "utf-8"))
```

Note: Header names are not case-sensitive in HTTP (or in this module).

{{< imgcap title="03.py" src="03.png" >}}

# Reading The Body of POST Requests
To handle POST requests we need to implement `do_POST` (surprise). To read the
body of the POST request we:

1. Read the `Content-Length` header in the incoming request.
2. Read that many bytes from `self.rfile`.
    1. I could not find a way to read "all bytes" in `rfile`. I had to rely on
       the `Content-Length` header.

```python
def do_POST(self):
    # read the content-length header
    content_length = int(self.headers.get("Content-Length"))
    # read that many bytes from the body of the request
    body = self.rfile.read(content_length)

    self.send_response(200)
    self.end_headers()
    # echo the body in the response
    self.wfile.write(body)
```

{{< imgcap title="04.py" src="04.png" >}}

# Server Over TLS
First, you need to create a private key and certificate in `pem` format. To
create a self-signed certificate/key in one line with OpenSSL:

```
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
```

Then modify the last lines of the original script to:

```python
httpd = HTTPServer(('localhost', 443), MyHandler)
httpd.socket = ssl.wrap_socket(httpd.socket, server_side=True, certfile="certificate.pem", keyfile="key.pem")
httpd.serve_forever()
```
