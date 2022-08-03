import httpx
from collections import OrderedDict
from .sync import TorTransport


class TorClient(httpx.Client):
    def __init__(self, proxy_ip: str, proxy_port: int):

        headers_list = [
            ('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'),
            ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'),
            ('Accept-Language', 'en-US,en;q=0.5'),
            ('Accept-Encoding', 'gzip, deflate, br'),
            ('Connection', 'keep-alive'),
            ('Upgrade-Insecure-Requests', '1'),
            ('Sec-Fetch-Dest', 'document'),
            ('Sec-Fetch-Mode', 'navigate'),
            ('Sec-Fetch-Site', 'none'),
            ('Sec-Fetch-User', '?1'),
        ]

        headers = OrderedDict(headers_list)

        transport = TorTransport(
            proxy_ip=proxy_ip, proxy_port=proxy_port)

        super().__init__(transport=transport, headers=headers)

    def new_identity(self):
        self._transport.reset()
        # probably do signal newnym to control port
