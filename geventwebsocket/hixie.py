import re
import struct
import hashlib
from socket import error

from . import exceptions as exc
from .websocket import WebSocket


__all__ = ['upgrade_connection']


class SecKeyError(Exception):
    """
    Raised if supplied Sec-WebSocket-Key* http header is malformed.

    http://tools.ietf.org/html/draft-hixie-thewebsocketprotocol-76#section-1.3
    """


class BaseWebSocket(WebSocket):
    __slots__ = ()

    def send(self, message):
        """
        Send a frame over the websocket with message as its payload
        """
        if self.closed:
            raise exc.WebSocketError('The connection was closed')

        try:
            self._write('\x00' + message.encode('utf-8') + '\xff')
        except error:
            self.close()

            raise exc.WebSocketError('Socket is dead')
        except:
            self.close()

            raise

    def _read_message(self):
        buf = ''

        while True:
            # TODO: reading 1 byte at a time is quite inefficient
            byte = self._read(1)

            if not byte:
                raise exc.WebSocketError('Connection closed unexpectedly while '
                                         'reading message: %r' % (buf,))

            if byte == '\xff':
                return buf

            buf += byte

        return buf

    def receive(self):
        if self.closed:
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

            return buf.decode("utf-8")

        self.close()

        raise exc.WebSocketError("Received an invalid frame_type=%r" % (
            ord(frame_type),))


class WebSocketHixie76(BaseWebSocket):
    __slots__ = ()


class WebSocketHixie75(BaseWebSocket):
    __slots__ = ()



def _make_websocket(handler, environ):
    # all looks good, lets rock
    if environ['wsgi.websocket_version'] == 'hixie-75':
        ws = WebSocketHixie75(handler.socket, environ)
    elif environ['wsgi.websocket_version'] == 'hixie-76':
        ws = WebSocketHixie76(handler.socket, environ)
    else:
        raise exc.WebSocketError('Unknown websocket version')

    environ['wsgi.websocket'] = ws

    headers = [
        ("Upgrade", "WebSocket"),
        ("Connection", "Upgrade"),
    ]

    prefix = ''

    if environ['wsgi.websocket_version'] == 'hixie-76':
        prefix = 'Sec-'

    if handler.ws_url:
        headers.append((prefix + 'WebSocket-Location', handler.ws_url))

    if ws.protocol:
        headers.append((prefix + 'WebSocket-Protocol', ws.protocol))

    if ws.origin:
        headers.append((prefix + 'WebSocket-Origin', ws.origin))

    handler.start_response('101 WebSocket Protocol Handshake', headers)


def upgrade_connection(handler, environ):
    key1 = environ.get('HTTP_SEC_WEBSOCKET_KEY1', None)
    key2 = environ.get('HTTP_SEC_WEBSOCKET_KEY2', None)

    if key1 is None:
        environ['wsgi.websocket_version'] = 'hixie-75'

        return _make_websocket(handler, environ)

    if not key1:
        msg = "400: Sec-WebSocket-Key1 header is empty"

        handler.log_error(msg)
        handler.start_response('400 Bad Request', [])

        return [msg]

    if not key2:
        msg = "400: Sec-WebSocket-Key2 header is missing/empty"

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

    if len(key3) != 8:
        raise exc.WebSocketError('Unexpected EOF while reading key3')

    challenge_key = struct.pack("!II", part1, part2) + key3
    challenge = hashlib.md5(challenge_key).digest()

    handler.socket.sendall(challenge)

    environ['wsgi.websocket_version'] = 'hixie-76'

    return _make_websocket(handler, environ)


def get_key_value(key):
    try:
        key_number = int(re.sub("\\D", "", key))
    except (ValueError, TypeError):
        raise SecKeyError('Invalid value for key')

    spaces = re.subn(" ", "", key)[1]

    if key_number % spaces != 0:
        raise SecKeyError("key_number %d is not an integral multiple of "
                          "spaces %d" % (key_number, spaces))

    return key_number / spaces
