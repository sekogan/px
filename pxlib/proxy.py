import os
import select
import socket
import time
import traceback

# Python 2.x vs 3.x support
try:
    import http.server as httpserver
    import urllib.parse as urlparse
except ImportError:
    import SimpleHTTPServer as httpserver
    import urlparse

from pxlib.glob import *

import pxlib.auth
import pxlib.config
import pxlib.windows

class Response(object):
    __slots__ = ["code", "length", "headers", "data", "body", "chunked", "close"]

    def __init__(self, code=503):
        self.code = code

        self.length = 0

        self.headers = []
        self.data = None

        self.body = False
        self.chunked = False
        self.close = False

###
# Proxy handler

class Proxy(httpserver.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Contains the proxy servers responsible for the url this Proxy instance
    # (aka thread) serves
    proxy_servers = []
    proxy_socket = None

    def handle_one_request(self):
        try:
            httpserver.SimpleHTTPRequestHandler.handle_one_request(self)
        except socket.error as e:
            dprint("Socket error: %s" % e)
            if not hasattr(self, "_host_disconnected"):
                self._host_disconnected = 1
                dprint("Host disconnected")
            elif self._host_disconnected < State.max_disconnect:
                self._host_disconnected += 1
                dprint("Host disconnected: %d" % self._host_disconnected)
            else:
                dprint("Closed connection to avoid infinite loop")
                self.close_connection = True

    def address_string(self):
        host, port = self.client_address[:2]
        #return socket.getfqdn(host)
        return host

    def log_message(self, format, *args):
        dprint(format % args)

    def do_socket_connect(self, destination=None):
        # Already connected?
        if self.proxy_socket is not None:
            return True

        dests = list(self.proxy_servers) if destination is None else [
            destination]
        for dest in dests:
            dprint("New connection: " + str(dest))
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                proxy_socket.connect(dest)
                self.proxy_address = dest
                self.proxy_socket = proxy_socket
                break
            except Exception as e:
                dprint("Connect failed: %s" % e)
                # move a non reachable proxy to the end of the proxy list;
                if len(self.proxy_servers) > 1:
                    # append first and then remove, this should ensure thread
                    # safety with manual configurated proxies (in this case
                    # self.proxy_servers references the shared
                    # State.proxy_server)
                    self.proxy_servers.append(dest)
                    self.proxy_servers.remove(dest)

        if self.proxy_socket is not None:
            return True

        return False

    def do_socket(self, xheaders={}, destination=None):
        dprint("Entering")

        # Connect to proxy or destination
        if not self.do_socket_connect(destination):
            return Response(408)

        # No chit chat on SSL
        if destination is not None and self.command == "CONNECT":
            return Response(200)

        cl = 0
        chk = False
        expect = False
        keepalive = False
        ua = False
        cmdstr = "%s %s %s\r\n" % (self.command, self.path, self.request_version)
        self.proxy_socket.sendall(cmdstr.encode("utf-8"))
        dprint(cmdstr.strip())
        for header in self.headers:
            hlower = header.lower()
            if hlower == "user-agent" and State.useragent != "":
                ua = True
                h = "%s: %s\r\n" % (header, State.useragent)
            else:
                h = "%s: %s\r\n" % (header, self.headers[header])

            self.proxy_socket.sendall(h.encode("utf-8"))
            if hlower != "authorization":
                dprint("Sending %s" % h.strip())
            else:
                dprint("Sending %s: sanitized len(%d)" % (
                    header, len(self.headers[header])))

            if hlower == "content-length":
                cl = int(self.headers[header])
            elif (hlower == "expect" and
                    self.headers[header].lower() == "100-continue"):
                expect = True
            elif hlower == "proxy-connection":
                keepalive = True
            elif (hlower == "transfer-encoding" and
                    self.headers[header].lower() == "chunked"):
                dprint("CHUNKED data")
                chk = True

        if not keepalive and self.request_version.lower() == "http/1.0":
            xheaders["Proxy-Connection"] = "keep-alive"

        if not ua and State.useragent != "":
            xheaders["User-Agent"] = State.useragent

        for header in xheaders:
            h = ("%s: %s\r\n" % (header, xheaders[header])).encode("utf-8")
            self.proxy_socket.sendall(h)
            if header.lower() != "proxy-authorization":
                dprint("Sending extra %s" % h.strip())
            else:
                dprint("Sending extra %s: sanitized len(%d)" % (
                    header, len(xheaders[header])))
        self.proxy_socket.sendall(b"\r\n")

        if self.command in ["POST", "PUT", "PATCH"]:
            if not hasattr(self, "body"):
                dprint("Getting body for POST/PUT/PATCH")
                if cl:
                    self.body = self.rfile.read(cl)
                else:
                    self.body = self.rfile.read()

            dprint("Sending body for POST/PUT/PATCH: %d = %d" % (
                cl or -1, len(self.body)))
            self.proxy_socket.sendall(self.body)

        self.proxy_fp = self.proxy_socket.makefile("rb")

        resp = Response()

        if self.command != "HEAD":
            resp.body = True

        # Response code
        for i in range(2):
            dprint("Reading response code")
            line = self.proxy_fp.readline(State.max_line)
            if line == b"\r\n":
                line = self.proxy_fp.readline(State.max_line)
            try:
                resp.code = int(line.split()[1])
            except (ValueError, IndexError):
                dprint("Bad response %s" % line)
                if line == b"":
                    dprint("Client closed connection")
                    return Response(444)
            if (b"connection established" in line.lower() or
                    resp.code == 204 or resp.code == 304):
                resp.body = False
            dprint("Response code: %d " % resp.code + str(resp.body))

            # Get response again if 100-Continue
            if not (expect and resp.code == 100):
                break

        # Headers
        dprint("Reading response headers")
        while not State.exit:
            line = self.proxy_fp.readline(State.max_line).decode("utf-8")
            if line == b"":
                if self.proxy_socket:
                    self.proxy_socket.shutdown(socket.SHUT_WR)
                    self.proxy_socket.close()
                    self.proxy_socket = None
                dprint("Proxy closed connection: %s" % resp.code)
                return Response(444)
            if line == "\r\n":
                break
            nv = line.split(":", 1)
            if len(nv) != 2:
                dprint("Bad header =>%s<=" % line)
                continue
            name = nv[0].strip()
            value = nv[1].strip()
            resp.headers.append((name, value))
            if name.lower() != "proxy-authenticate":
                dprint("Received %s: %s" % (name, value))
            else:
                dprint("Received %s: sanitized (%d)" % (name, len(value)))

            if name.lower() == "content-length":
                resp.length = int(value)
                if not resp.length:
                    resp.body = False
            elif (name.lower() == "transfer-encoding" and
                    value.lower() == "chunked"):
                resp.chunked = True
                resp.body = True
            elif (name.lower() in ["proxy-connection", "connection"] and
                    value.lower() == "close"):
                resp.close = True

        return resp

    def do_proxy_type(self):
        # Connect to proxy
        if not hasattr(self, "proxy_address"):
            if not self.do_socket_connect():
                return Response(408), None

        State.proxy_type_lock.acquire()
        try:
            # Read State.proxy_type only once and use value for function return
            # if it is not None; State.proxy_type should only be read here to
            # avoid getting None after successfully identifying the proxy type
            # if another thread clears it with load_proxy
            proxy_type = State.proxy_type.get(self.proxy_address, State.auth)
            if proxy_type is None:
                # New proxy, don't know type yet
                dprint("Searching proxy type")
                resp = self.do_socket()

                proxy_auth = ""
                for header in resp.headers:
                    if header[0].lower() == "proxy-authenticate":
                        proxy_auth += header[1] + " "

                for auth in proxy_auth.split():
                    auth = auth.upper()
                    if auth in ["NTLM", "KERBEROS", "NEGOTIATE", "BASIC"]:
                        proxy_type = auth
                        break

                if proxy_type is not None:
                    # Writing State.proxy_type only once but use local variable
                    # as return value to avoid losing the query result (for the
                    # current request) by clearing State.proxy_type in load_proxy
                    State.proxy_type[self.proxy_address] = proxy_type

                dprint("Auth mechanisms: " + proxy_auth)
                dprint("Selected: " + str(self.proxy_address) + ": " +
                    str(proxy_type))

                return resp, proxy_type

            return Response(407), proxy_type
        finally:
            State.proxy_type_lock.release()

    def do_transaction(self):
        dprint("Entering")

        ipport = self.get_destination()
        if ipport not in [False, True]:
            dprint("Skipping auth proxying")
            resp = self.do_socket(destination=ipport)
        elif ipport:
            # Get proxy type directly from do_proxy_type instead by accessing
            # State.proxy_type do avoid a race condition with clearing
            # State.proxy_type in load_proxy which sometimes led to a proxy type
            # of None (clearing State.proxy_type in one thread was done after
            # another thread's do_proxy_type but before accessing
            # State.proxy_type in the second thread)
            resp, proxy_type = self.do_proxy_type()
            if resp.code == 407:
                # Unknown auth mechanism
                if proxy_type is None:
                    dprint("Unknown auth mechanism expected")
                    return resp

                # Generate auth message
                ntlm = pxlib.auth.AuthMessageGenerator(proxy_type, self.proxy_address[0])
                ntlm_resp = ntlm.get_response()
                if ntlm_resp is None:
                    dprint("Bad auth response")
                    return Response(503)

                self.fwd_data(resp, flush=True)

                hconnection = ""
                for i in ["connection", "Connection"]:
                    if i in self.headers:
                        hconnection = self.headers[i]
                        del self.headers[i]
                        dprint("Remove header %s: %s" % (i, hconnection))

                # Send auth message
                resp = self.do_socket({
                    "Proxy-Authorization": "%s %s" % (proxy_type, ntlm_resp),
                    "Proxy-Connection": "Keep-Alive"
                })
                if resp.code == 407:
                    dprint("Auth required")
                    ntlm_challenge = ""
                    for header in resp.headers:
                        if (header[0].lower() == "proxy-authenticate" and
                                proxy_type in header[1].upper()):
                            h = header[1].split()
                            if len(h) == 2:
                                ntlm_challenge = h[1]
                                break

                    if ntlm_challenge:
                        dprint("Challenged")
                        ntlm_resp = ntlm.get_response(ntlm_challenge)
                        if ntlm_resp is None:
                            dprint("Bad auth response")
                            return Response(503)

                        self.fwd_data(resp, flush=True)

                        if hconnection != "":
                            self.headers["Connection"] = hconnection
                            dprint("Restore header Connection: " + hconnection)

                        # Reply to challenge
                        resp = self.do_socket({
                            "Proxy-Authorization": "%s %s" % (
                                proxy_type, ntlm_resp)
                        })
                    else:
                        dprint("Didn't get challenge, auth didn't work")
                else:
                    dprint("No auth required cached")
            else:
                dprint("No auth required")
        else:
            dprint("No proxy server specified and not in noproxy list")
            return Response(501)

        return resp

    def do_HEAD(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PAC(self):
        resp = Response(404)
        if State.proxy_mode in [MODE_PAC, MODE_CONFIG_PAC]:
            pac = State.pac
            if "file://" in State.pac:
                pac = file_url_to_local_path(State.pac)
            dprint(pac)
            try:
                resp.code = 200
                with open(pac) as p:
                    resp.data = p.read().encode("utf-8")
                    resp.body = True
                resp.headers = [
                    ("Content-Length", len(resp.data)),
                    ("Content-Type", "application/x-ns-proxy-autoconfig")
                ]
            except:
                traceback.print_exc(file=sys.stdout)

        return resp

    def do_GET(self):
        dprint("Entering")

        dprint("Path = " + self.path)
        if "/PxPACFile.pac" in self.path:
            resp = self.do_PAC()
        else:
            resp = self.do_transaction()

        if resp.code >= 400:
            dprint("Error %d" % resp.code)

        self.fwd_resp(resp)

        dprint("Done")

    def do_POST(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PUT(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_DELETE(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PATCH(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_CONNECT(self):
        dprint("Entering")

        for i in ["connection", "Connection"]:
            if i in self.headers:
                del self.headers[i]
                dprint("Remove header " + i)

        cl = 0
        cs = 0
        resp = self.do_transaction()
        if resp.code >= 400:
            dprint("Error %d" % resp.code)
            self.fwd_resp(resp)
        else:
            # Proxy connection may be already closed due to header
            # (Proxy-)Connection: close received from proxy -> forward this to
            # the client
            if self.proxy_socket is None:
                dprint("Proxy connection closed")
                self.send_response(200, "True")
                self.send_header("Proxy-Connection", "close")
                self.end_headers()
            else:
                dprint("Tunneling through proxy")
                self.send_response(200, "Connection established")
                self.send_header("Proxy-Agent", self.version_string())
                self.end_headers()

                # sockets will be removed from these lists, when they are
                # detected as closed by remote host; wlist contains sockets
                # only when data has to be written
                rlist = [self.connection, self.proxy_socket]
                wlist = []

                # data to be written to client connection and proxy socket
                cdata = []
                sdata = []
                idle = State.config.getint("settings", "idle")
                max_idle = time.time() + idle
                while not State.exit and (rlist or wlist):
                    (ins, outs, exs) = select.select(rlist, wlist, rlist, idle)
                    if exs:
                        break
                    if ins:
                        for i in ins:
                            if i is self.proxy_socket:
                                out = self.connection
                                wdata = cdata
                                source = "proxy"
                            else:
                                out = self.proxy_socket
                                wdata = sdata
                                source = "client"

                            data = i.recv(4096)
                            if data:
                                cl += len(data)
                                # Prepare data to send it later in outs section
                                wdata.append(data)
                                if out not in outs:
                                    outs.append(out)
                                max_idle = time.time() + idle
                            else:
                                # No data means connection closed by remote host
                                dprint("Connection closed by %s" % source)
                                # Because tunnel is closed on one end there is
                                # no need to read from both ends
                                del rlist[:]
                                # Do not write anymore to the closed end
                                if i in wlist:
                                    wlist.remove(i)
                                if i in outs:
                                    outs.remove(i)
                    if outs:
                        for o in outs:
                            if o is self.proxy_socket:
                                wdata = sdata
                            else:
                                wdata = cdata
                            data = wdata[0]
                            # socket.send() may sending only a part of the data
                            # (as documentation says). To ensure sending all data
                            bsnt = o.send(data)
                            if bsnt > 0:
                                if bsnt < len(data):
                                    # Not all data was sent; store data not
                                    # sent and ensure select() get's it when
                                    # the socket can be written again
                                    wdata[0] = data[bsnt:]
                                    if o not in wlist:
                                        wlist.append(o)
                                else:
                                    wdata.pop(0)
                                    if not data and o in wlist:
                                        wlist.remove(o)
                                cs += bsnt
                            else:
                                dprint("No data sent")
                        max_idle = time.time() + idle
                    if max_idle < time.time():
                        # No data in timeout seconds
                        dprint("Proxy connection timeout")
                        break

        # After serving the proxy tunnel it could not be used for samething else.
        # A proxy doesn't really know, when a proxy tunnnel isn't needed any
        # more (there is no content length for data). So servings will be ended
        # either after timeout seconds without data transfer or when at least
        # one side closes the connection. Close both proxy and client
        # connection if still open.
        if self.proxy_socket is not None:
            dprint("Cleanup proxy connection")
            self.proxy_socket.shutdown(socket.SHUT_WR)
            self.proxy_socket.close()
            self.proxy_socket = None
        self.close_connection = True

        dprint("%d bytes read, %d bytes written" % (cl, cs))

        dprint("Done")

    def fwd_data(self, resp, flush=False):
        cl = resp.length
        dprint("Reading response data")
        if resp.body:
            if cl:
                dprint("Content length %d" % cl)
                while cl > 0:
                    if cl > 4096:
                        l = 4096
                        cl -= l
                    else:
                        l = cl
                        cl = 0
                    d = self.proxy_fp.read(l)
                    if not flush:
                        self.wfile.write(d)
            elif resp.chunked:
                dprint("Chunked encoding")
                while not State.exit:
                    line = self.proxy_fp.readline(State.max_line)
                    if not flush:
                        self.wfile.write(line)
                    line = line.decode("utf-8").strip()
                    if not len(line):
                        dprint("Blank chunk size")
                        break
                    else:
                        try:
                            csize = int(line, 16) + 2
                            dprint("Chunk of size %d" % csize)
                        except ValueError:
                            dprint("Bad chunk size '%s'" % line)
                            continue
                    d = self.proxy_fp.read(csize)
                    if not flush:
                        self.wfile.write(d)
                    if csize == 2:
                        dprint("No more chunks")
                        break
                    if len(d) < csize:
                        dprint("Chunk size doesn't match data")
                        break
            elif resp.data is not None:
                dprint("Sending data string")
                if not flush:
                    self.wfile.write(resp.data)
            else:
                dprint("Not sure how much")
                while not State.exit:
                    time.sleep(0.1)
                    d = self.proxy_fp.read(1024)
                    if not flush:
                        self.wfile.write(d)
                    if len(d) < 1024:
                        break

        if resp.close and self.proxy_socket:
            dprint("Close proxy connection per header")
            self.proxy_socket.close()
            self.proxy_socket = None

    def fwd_resp(self, resp):
        dprint("Entering")
        self.send_response(resp.code)

        for header in resp.headers:
            dprint("Returning %s: %s" % (header[0], header[1]))
            self.send_header(header[0], header[1])

        self.end_headers()

        self.fwd_data(resp)

        dprint("Done")

    def get_destination(self):
        netloc = self.path
        path = "/"
        if self.command != "CONNECT":
            parse = urlparse.urlparse(self.path, allow_fragments=False)
            if parse.netloc:
                netloc = parse.netloc
            if ":" not in netloc:
                port = parse.port
                if not port:
                    if parse.scheme == "http":
                        port = 80
                    elif parse.scheme == "https":
                        port = 443
                    elif parse.scheme == "ftp":
                        port = 21
                netloc = netloc + ":" + str(port)

            path = parse.path or "/"
            if parse.params:
                path = path + ";" + parse.params
            if parse.query:
                path = path + "?" + parse.query
        dprint(netloc)

        # Check destination for noproxy first, before doing any expensive stuff
        # possibly involving connections
        if State.noproxy.size:
            addr = []
            spl = netloc.split(":", 1)
            try:
                addr = socket.getaddrinfo(spl[0], int(spl[1]))
            except socket.gaierror:
                # Couldn't resolve, let parent proxy try, #18
                dprint("Couldn't resolve host")
            if len(addr) and len(addr[0]) == 5:
                ipport = addr[0][4]
                dprint("%s => %s + %s" % (self.path, ipport, path))

                if ipport[0] in State.noproxy:
                    dprint("Direct connection from noproxy configuration")
                    self.path = path
                    return ipport

        # Get proxy mode and servers straight from load_proxy to avoid
        # threading issues
        (proxy_mode, self.proxy_servers) = load_proxy()
        if proxy_mode in [MODE_AUTO, MODE_PAC, MODE_CONFIG_PAC]:
            proxy_str = find_proxy_for_url(
                ("https://" if "://" not in self.path else "") + self.path)
            if proxy_str == "DIRECT":
                ipport = netloc.split(":")
                ipport[1] = int(ipport[1])
                dprint("Direct connection from PAC")
                self.path = path
                return tuple(ipport)

            if proxy_str:
                dprint("Proxy from PAC = " + str(proxy_str))
                # parse_proxy does not modify State.proxy_server any more,
                # it returns the proxy server tuples instead, because proxy_str
                # contains only the proxy servers for URL served by this thread
                self.proxy_servers = pxlib.config.parse_proxy(proxy_str)

        return True if self.proxy_servers else False

def file_url_to_local_path(file_url):
    parts = urlparse.urlparse(file_url)
    path = urlparse.unquote(parts.path)
    if path.startswith('/') and not path.startswith('//'):
        if len(parts.netloc) == 2 and parts.netloc[1] == ':':
            return parts.netloc + path
        return 'C:' + path
    if len(path) > 2 and path[1] == ':':
        return path

def load_proxy(quiet=False):
    # Return if proxies specified in Px config
    if State.proxy_mode in [MODE_CONFIG, MODE_CONFIG_PAC]:
        return (State.proxy_mode, State.proxy_server)

    # Do locking to avoid updating globally shared State object by multiple
    # threads simultaneously
    State.proxy_mode_lock.acquire()
    try:
        proxy_mode = State.proxy_mode
        proxy_servers = State.proxy_server
        # Check if need to refresh
        if (State.proxy_refresh is not None and
                time.time() - State.proxy_refresh <
                State.config.getint("settings", "proxyreload")):
            if not quiet:
                dprint("Skip proxy refresh")
            return (proxy_mode, proxy_servers)

        if os.name == "nt":
            (proxy_mode, proxy_servers) = pxlib.windows.load_proxy(quiet)

        State.proxy_refresh = time.time()
        if not quiet:
            dprint("Proxy mode = " + str(proxy_mode))
        State.proxy_mode = proxy_mode
        State.proxy_server = proxy_servers

        # Clear proxy types on proxy server update
        State.proxy_type = {}

    finally:
        State.proxy_mode_lock.release()

    return (proxy_mode, proxy_servers)

def find_proxy_for_url(url):
    proxy_str = ""
    if State.proxy_mode == MODE_AUTO:
        proxy_str = pxlib.windows.winhttp_find_proxy_for_url(url, autodetect=True)

    elif State.proxy_mode in [MODE_PAC, MODE_CONFIG_PAC]:
        pac = State.pac
        if "file://" in State.pac or not State.pac.startswith("http"):
            host = State.config.get("proxy", "listen") or "localhost"
            port = State.config.getint("proxy", "port")
            pac = "http://%s:%d/PxPACFile.pac" % (host, port)
            dprint("PAC URL is local: " + pac)
        if os.name == "nt":
            proxy_str = pxlib.windows.winhttp_find_proxy_for_url(url, pac_url=pac)

    # Handle edge case if the result is a list that starts with DIRECT. Assume
    # everything should be direct as the string DIRECT is tested explicitly in
    # get_destination
    if proxy_str.startswith("DIRECT,"):
        proxy_str = "DIRECT"

    # If the proxy_str it still empty at this point, then there is no proxy
    # configured. Try to do a direct connection.
    if proxy_str == "":
        proxy_str = "DIRECT"

    dprint("Proxy found: " + proxy_str)
    return proxy_str
