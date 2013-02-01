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
    __slots__ = (
        '_buffer',
    )

    def __init__(self, socket, environ, rfile):
        super(BaseWebSocket, self).__init__(socket, environ, rfile)

        self._buffer = ''

    def send_frame(self, data):
        """
        Send a frame over the websocket with data as its payload.

        This is an internal method as calling this will not cleanup correctly
        if an exception is called. Use `send` instead.

        :param data: A utf-8 encoded bytestring.
        """
        try:
            self._write('\x00' + data + '\xff')
        except error:
            raise exc.WebSocketError('Socket is dead')

    def send(self, message):
        """
        Send a frame over the websocket with message as its payload
        """
        if self.closed:
            raise exc.WebSocketError('The connection was closed')

        if not message:
            # sending an empty frame is considered a close frame ..
            return

        self.send_frame(message.encode('utf-8'))

    def close(self):
        """
        Close the websocket. The draft hixie protocols say to send an empty
        frame as the close frame.
        """
        if self.closed:
            return

        try:
            # an empty frame is a close frame
            self.send_frame('')
        except exc.WebSocketError:
            # failed to write the closing frame but it's ok because we're
            # closing the socket anyway.
            pass
        finally:
            self._buffer = None
            super(BaseWebSocket, self).close()

    def _read_from_buffer(self, size):
        socket_read_size = size - len(self._buffer)

        data = self._buffer[:size]

        if socket_read_size:
            data += self._read(socket_read_size)

        self._buffer = self._buffer[size:]

        return data

    def _write_to_buffer(self, data):
        self._buffer += data

    def read_message(self):
        """
        Return the next message from the socket.

        This is an internal method as calling this will not cleanup correctly
        if an exception is called. Use `receive` instead.
        """
        frame_type = self._read_from_buffer(1)

        if not frame_type:
            return

        if frame_type != '\x00':
            raise exc.ProtocolError("Received an invalid frame_type=%r" % (
                ord(frame_type),))

        buf = ''

        while True:
            data = self._read_from_buffer(1024)

            chunks = data.split('\xff', 1)

            if len(chunks) == 1:
                # read only part of a message
                buf += data

                continue

            fragment, remaining = chunks

            # full frame, with some remaining
            buf += fragment

            if remaining:
                self._write_to_buffer(remaining)

            break

        return buf.decode('utf-8')

    def receive(self):
        """
        Read and return a message from the stream. If `None` is returned, then
        the socket is considered closed/errored.
        """
        if self.closed:
            return

        try:
            msg = self.read_message()
        except error:
            raise exc.WebSocketError('Socket is dead')

        if not msg:
            self.close()

        return msg


class WebSocketHixie76(BaseWebSocket):
    __slots__ = ()


class WebSocketHixie75(BaseWebSocket):
    __slots__ = ()

    @property
    def protocol(self):
        if not self.environ:
            return

        return self.environ.get('HTTP_WEBSOCKET_PROTOCOL')


def _make_websocket(handler, environ):
    # all looks good, lets rock
    if environ['wsgi.websocket_version'] == 'hixie-75':
        ws = WebSocketHixie75(handler.socket, environ, handler.rfile)
    elif environ['wsgi.websocket_version'] == 'hixie-76':
        ws = WebSocketHixie76(handler.socket, environ, handler.rfile)
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
    key3 = handler.rfile.read(8)

    if len(key3) != 8:
        raise exc.WebSocketError('Unexpected EOF while reading key3')

    challenge_key = struct.pack("!II", part1, part2) + key3
    challenge = hashlib.md5(challenge_key).digest()

    environ['wsgi.websocket_version'] = 'hixie-76'

    _make_websocket(handler, environ)

    handler.write(challenge)


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
