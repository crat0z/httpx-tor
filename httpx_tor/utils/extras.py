import random
from string import ascii_letters
from nss import io


def _random_string() -> str:
    return ''.join(random.choice(ascii_letters) for _ in range(8))


def seconds_to_interval(val):
    if val is not None:
        return io.seconds_to_interval(int(val))
    else:
        return io.PR_INTERVAL_NO_TIMEOUT
