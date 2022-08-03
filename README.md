# httpx-tor
A Python HTTP client that tries to imitate Tor Browser, based on `httpx` and `python-nss`

## Why?
To get around restrictions of course. Across many different sites, I've found there to be a few levels of restriction placed on Tor users. From least to most restricted:

- Tor users are allowed.
- Tor users that send Tor Browser's HTTP headers (or anything that looks like a real browser) are allowed.
- Tor users that do the above, and also send similar/identical SSL handshake to Tor Browser are allowed. (Where `httpx-tor` currently stands)
- ... ? unknown
- Tor users that are using Tor Browser with JavaScript enabled are allowed.
- Tor users are always banned/blocked, regardless of anything else. Essentially IP bans.

## What's special then?
- Uses Tor Browser headers.
- Sends identical SSL ClientHello as Tor Browser.
- Negotiates HTTP/2 like every browser does.

## Future
- Proper handling of Fetch metadata request headers
- ... more as I think of them

## Example
As previously mentioned, `httpx-tor` is based off of `httpx`, and exposes a client practically identical to `httpx.Client`:

```python
from httpx_tor import TorClient

client = TorClient(proxy_ip='127.0.0.1', proxy_port=9050)

# below URL will give Cloudflare captcha with other clients
r = client.get('https://json.geoiplookup.io')
```

`httpx_tor.TorClient` inherits from `httpx.Client`, making the transition to `TorClient` easy. For more information, read the [httpx docs](https://www.python-httpx.org/). For users familiar with `requests`, read the [requests compatibility guide](https://www.python-httpx.org/compatibility/).

## Installation
As of writing, `python-nss`, the package that provides SSL for `httpx-tor`, has been half abandoned. The version available on PyPI does not expose some functions and many constants that `httpx-tor` uses.

Install `python-nss`:
### Ubuntu
```bash
sudo apt install libnss3-dev libnspr4-dev libnss3-tools
```
### Fedora
```bash
sudo dnf install nss-devel nspr-devel nss-tools
```
Then, init the git submodule and install with
```bash
git submodule update --init --recursive
cd python-nss
python setup.py install
```
Once you have `python-nss` installed, you can install this package:
```bash
cd ..
pip install .
```

## NSS certificate database
You might need to initialize the NSS cert db. By default, `httpx-tor` looks in `$HOME/.pki/nssdb` for a cert DB. If this does not exist, you will get an exception when trying to connect.
```bash
mkdir ~/.pki/nssdb
certutil -N --empty-password -d sql:$HOME/.pki/nssdb
```
You now need to add CA certs to the db:
```bash
modutil -add ca_certs -libfile $LIBFILE -dbdir sql:$HOME/.pki/nssdb
```
`LIBFILE` is either located at `/usr/lib/libnssckbi.so` on Ubuntu, or `/usr/lib64/libnssckbi.so` on Fedora.