import nss
import nss.ssl as ssl
import nss.io as io
import os

_groups = [
    ssl.ssl_grp_ec_curve25519,
    ssl.ssl_grp_ec_secp256r1,
    ssl.ssl_grp_ec_secp384r1,
    ssl.ssl_grp_ec_secp521r1,
    ssl.ssl_grp_ffdhe_2048,
    ssl.ssl_grp_ffdhe_3072,
]


def seconds_to_interval(val):
    if val is not None:
        return io.seconds_to_interval(int(val))
    else:
        return io.PR_INTERVAL_NO_TIMEOUT


def create_ssl_socket(hostname, port, keep_alive=None):
    # initialize nss
    if not nss.nss_is_initialized():
        home = os.getenv('HOME')
        nss.nss_init(f'sql:{home}/.pki/nssdb')

        # set defaults for sockets
        ssl.set_ssl_default_option(ssl.SSL_SECURITY, False)
        ssl.set_ssl_default_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        ssl.set_ssl_default_option(ssl.SSL_HANDSHAKE_AS_SERVER, False)

        # commonInit
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_SSL2, False)
        ssl.set_ssl_default_option(ssl.SSL_V2_COMPATIBLE_HELLO, False)

        # torbrowser settings
        ssl.set_ssl_default_option(ssl.SSL_REQUIRE_SAFE_NEGOTIATION, 0)
        ssl.set_ssl_default_option(
            ssl.SSL_ENABLE_RENEGOTIATION, ssl.SSL_RENEGOTIATE_REQUIRES_XTN)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_EXTENDED_MASTER_SECRET, 1)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_FALSE_START, 1)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_ALPN, 1)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_0RTT_DATA, 1)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_POST_HANDSHAKE_AUTH, 0)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_DELEGATED_CREDENTIALS, 1)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_HELLO_DOWNGRADE_CHECK, 1)

        # enable OCSP checking. the below actually does the checking,
        # but it isn't necessary to be enabled in order to get identical
        # ClientHello as TBB.
        # nss.enable_ocsp_checking()
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_OCSP_STAPLING, 1)
        ssl.set_ssl_default_option(ssl.SSL_NO_CACHE, 1)
        ssl.set_ssl_default_option(ssl.SSL_ENABLE_TLS13_COMPAT_MODE, 1)
        ssl.set_domestic_policy()

        ciphers = [
            ssl.TLS_AES_128_GCM_SHA256,
            ssl.TLS_CHACHA20_POLY1305_SHA256,
            ssl.TLS_AES_256_GCM_SHA384,
            ssl.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ssl.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ssl.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            ssl.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            ssl.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            ssl.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            ssl.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
            ssl.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
            ssl.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            ssl.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            ssl.TLS_RSA_WITH_AES_128_GCM_SHA256,
            ssl.TLS_RSA_WITH_AES_256_GCM_SHA384,
            ssl.TLS_RSA_WITH_AES_128_CBC_SHA,
            ssl.TLS_RSA_WITH_AES_256_CBC_SHA,
            ssl.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        ]

        # disable all
        for cipher in ssl.ssl_implemented_ciphers:
            ssl.set_default_cipher_pref(cipher, False)

        # enable good ones
        for cipher in ciphers:
            ssl.set_cipher_policy(cipher, True)
            ssl.set_default_cipher_pref(cipher, True)

    addr_info = io.AddrInfo(hostname)

    for addr in addr_info:
        addr.port = port
        sock = ssl.SSLSocket(addr.family)
        sock.set_socket_option(io.PR_SockOpt_Keepalive, True)

        sock.send_additional_keyshares(1)
        sock.named_group_config(_groups)
        sock.set_hostname(hostname)

        sock.connect(addr, seconds_to_interval(keep_alive))

        return sock
