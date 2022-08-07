from typing import Tuple, List
from utils.socket import create_ssl_socket
from utils.extras import _random_string, seconds_to_interval
import nss.ssl as ssl
import httpx
from httpcore.backends.base import NetworkStream
from httpcore._sync.connection_pool import ConnectionPool
from httpcore._models import Origin
from httpcore._sync.interfaces import ConnectionInterface
from httpcore._sync.socks_proxy import Socks5Connection, _init_socks5_connection
from httpcore._sync.http11 import HTTP11Connection
from httpcore._sync.http2 import HTTP2Connection
from httpcore._models import Request, Response
from httpcore._trace import Trace
from httpcore._exceptions import ConnectionNotAvailable
from httpcore._models import URL
from httpx._transports.default import map_httpcore_exceptions, ResponseStream


def _handshake_callback(sock, stream):

    # set result of handshake needed for alpn
    (state, result) = sock.get_next_proto()

    if result:
        stream.alpn_result = result
    else:
        stream.alpn_result = 'http/1.1'


class TorStream(NetworkStream):

    def __init__(self, ip, port, timeout):
        self.sock = create_ssl_socket(ip, port, timeout)
        self.alpn_req = None
        self.alpn_result = None

    def read(self, max_bytes: int, timeout=None) -> bytes:
        return self.sock.recv(max_bytes, seconds_to_interval(timeout))

    def write(self, buffer: bytes, timeout=None) -> None:
        return self.sock.send(buffer, seconds_to_interval(timeout))

    def close(self) -> None:
        self.sock.close()

    def do_handshake(self, hostname: str, protos: List[bytes] | None):
        # enable SSL
        self.sock.set_ssl_option(ssl.SSL_SECURITY, True)
        self.sock.reset_handshake(False)
        self.sock.set_hostname(hostname.decode('ascii'))

        # setup ALPN
        if protos is not None:
            self.alpn_req = protos
            self.sock.set_next_proto(protos)
            self.sock.set_handshake_callback(_handshake_callback, self)

        self.sock.force_handshake()

        if protos is not None:
            while self.alpn_result is None:
                pass

        return self.alpn_result


class TorConnection(Socks5Connection):

    def __init__(self, proxy_origin: Origin, remote_origin: Origin, proxy_auth: Tuple[bytes, bytes], keepalive_expiry=None) -> None:

        super().__init__(proxy_origin=proxy_origin, remote_origin=remote_origin,
                         proxy_auth=proxy_auth, ssl_context=None, keepalive_expiry=keepalive_expiry, http1=True, http2=True)

    def handle_request(self, request: Request) -> Response:

        # copypasted from SOCKS5Connection.handle_request(), replaced parts to work with nss
        timeouts = request.extensions.get("timeout", {})
        timeout = timeouts.get("connect", None)

        with self._connect_lock:
            if self._connection is None:
                try:
                    kwargs = {
                        "host": self._proxy_origin.host.decode("ascii"),
                        "port": self._proxy_origin.port,
                        "timeout": timeout,
                    }
                    with Trace("connection.connect_tcp", request, kwargs) as trace:
                        stream = TorStream(
                            self._proxy_origin.host.decode("ascii"), self._proxy_origin.port, timeout)
                        trace.return_value = stream

                    # Connect to the remote host using socks5
                    kwargs = {
                        "stream": stream,
                        "host": self._remote_origin.host.decode("ascii"),
                        "port": self._remote_origin.port,
                        "auth": self._proxy_auth,
                    }
                    with Trace(
                        "connection.setup_socks5_connection", request, kwargs
                    ) as trace:
                        _init_socks5_connection(**kwargs)
                        trace.return_value = stream

                    http2_negotiated = False

                    # upgrade to SSL, if necessary
                    if self._remote_origin.scheme == b'https':

                        protos = [b'h2', b'http/1.1']

                        result = stream.do_handshake(
                            self._remote_origin.host, protos)

                        if result == b'h2':
                            http2_negotiated = True

                    if http2_negotiated:
                        self._connection = HTTP2Connection(
                            origin=self._remote_origin, stream=stream, keepalive_expiry=self._keepalive_expiry)

                    else:
                        self._connection = HTTP11Connection(
                            origin=self._remote_origin, stream=stream, keepalive_expiry=self._keepalive_expiry)

                except BaseException as e:
                    self._connect_failed = True
                    raise e
            elif not self._connection.is_available():
                raise ConnectionNotAvailable()

        return self._connection.handle_request(request)


class TorTransport(ConnectionPool):

    def __init__(self, proxy_ip: str, proxy_port: int, max_connections=10, max_keepalives=10,
                 keepalive_expiry=30, retries=3):

        super().__init__(None, max_connections=max_connections,
                         max_keepalive_connections=max_keepalives, keepalive_expiry=keepalive_expiry,
                         http1=True, http2=True, retries=retries)

        self.proxy_origin = Origin(
            b"socks5", bytes(proxy_ip, 'ascii'), proxy_port)

        self.proxy_auths = {}

    def _proxy_auth_for_domain(self, target: Origin) -> Tuple[bytes, bytes]:

        proxy = self.proxy_auths.get(target.host, None)

        if proxy is not None:
            return proxy
        else:
            proxy = (_random_string(), _random_string())
            self.proxy_auths[target.host] = proxy
            return proxy

    def reset(self):
        with self._pool_lock:
            self.proxy_auths = {}
            for (idx, connection) in enumerate(self.connections):
                with connection._connect_lock:
                    connection.close()
                self._pool.pop(idx)

    def handle_request(self, request: httpx.Request) -> httpx.Response:

        req = Request(
            method=request.method,
            url=URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            resp = super().handle_request(req)

        return httpx.Response(
            status_code=resp.status,
            headers=resp.headers,
            stream=ResponseStream(resp.stream),
            extensions=resp.extensions,
        )

    def create_connection(self, origin: Origin) -> ConnectionInterface:
        return TorConnection(self.proxy_origin, origin, self._proxy_auth_for_domain(origin))
