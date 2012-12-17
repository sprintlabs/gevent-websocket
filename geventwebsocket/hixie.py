import re
import struct
import hashlib

from .exceptions import WebSocketError
from .websocket import WebSocket, encode_bytes


__all__ = ['WebSocketHixie']


class SecKeyError(Exception):
    """
    Raised if supplied Sec-WebSocket-Key* is malformed.

    http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76#section-1.3
    """


class WebSocketHixie(WebSocket):
    def send(self, message):
        message = encode_bytes(message)

        with self._writelock:
            self._write("\x00" + message + "\xff")

    def _read_message(self):
        buf = ''

        while True:
            # TODO: reading 1 byte at a time is quite inefficient
            byte = self._read(1)

            if not byte:
                raise WebSocketError('Connection closed unexpectedly while '
                                     'reading message: %r' % (buf,))

            if byte == '\xff':
                return buf

            buf += byte

        return buf

    def receive(self):
        if not self.socket:
            return

        frame_type = self._read(1)

        if not frame_type:
            # whoops, something went wrong
            self.close()

            return

        if frame_type == '\x00':
            try:
                buf = self._read_message()
            except:
                self.close()

                raise

            # XXX - Why the replace?
            return buf.decode("utf-8", "replace")

        self.close()

        raise WebSocketError("Received an invalid frame_type=%r" % (
            ord(frame_type),))


def _make_websocket(handler):
    environ = handler.environ

    # all looks good, lets rock
    ws = environ['wsgi.websocket'] = WebSocketHixie(handler.socket, environ)

    headers = [
        ("Upgrade", "WebSocket"),
        ("Connection", "Upgrade"),
        ("WebSocket-Location", handler.ws_url),
    ]

    if ws.protocol:
        headers.append(("Sec-WebSocket-Protocol", ws.protocol))

    if ws.origin:
        headers.append(("Sec-WebSocket-Origin", ws.origin))

    handler.start_response("101 Web Socket Protocol Handshake", headers)


def upgrade_connection(handler, environ):
    key1 = environ.get('HTTP_SEC_WEBSOCKET_KEY1', None)
    key2 = environ.get('HTTP_SEC_WEBSOCKET_KEY2', None)

    if key1 is None:
        environ['wsgi.websocket_version'] = 'hixie-75'

        return _make_websocket(handler)

    if not key1:
        msg = "400: Sec-WebSocket-Key1 header is empty"

        handler.log_error(msg)
        handler.start_response('400 Bad Request', [])

        return [msg]

    if not key2:
        msg = "400: Sec-WebSocket-Key1 header is missing/empty"

        handler.log_error(msg)
        handler.start_response('400 Bad Request', [])

        return [msg]

    try:
        part1 = get_key_value(key1)
        part2 = get_key_value(key2)
    except SecKeyError, e:
        msg = unicode(e)

        handler.log_error(msg)
        handler.start_response('400 Bad Request', [])

        return [msg]

    # This request should have 8 bytes of data in the body
    key3 = handler.socket.recv(8)

    challenge_key = struct.pack("!II", part1, part2) + key3
    challenge = hashlib.md5(challenge_key).digest()
    handler.socket.sendall(challenge)

    environ['wsgi.websocket_version'] = 'hixie-76'

    return _make_websocket(handler)


def get_key_value(key):
    key_number = int(re.sub("\\D", "", key))
    spaces = re.subn(" ", "", key)[1]

    if key_number % spaces != 0:
        raise SecKeyError("key_number %d is not an integral multiple of "
                          "spaces %d" % (key_number, spaces))

    return key_number / spaces
