import base64
import hashlib
import struct

from . import exceptions as exc
from .websocket import WebSocket, encode_bytes


__all__ = ['WebSocketHybi']


OPCODE_TEXT = 0x01
OPCODE_BINARY = 0x02
OPCODE_CLOSE = 0x08
OPCODE_PING = 0x09
OPCODE_PONG = 0x0a

FIN_MASK = 0x80
OPCODE_MASK = 0x0f
MASK_MASK = 0x80
LENGTH_MASK = 0x7f

# bitwise mask that will determine the reserved bits for a frame header
HEADER_RSV_MASK = 0x40 | 0x20 | 0x10


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SUPPORTED_VERSIONS = ('13', '8', '7')


class ConnectionClosed(Exception):
    """
    A special type of exception indicating that the remote endpoint closed the
    connection.
    """

    def __init__(self, code, message):
        self.code = code
        self.message = message


class WebSocketHybi(WebSocket):
    def _decode_bytes(self, bytes):
        if not bytes:
            return bytes

        try:
            return bytes.decode('utf-8')
        except ValueError:
            self.close(1007)

            raise

    def _read_frame(self):
        """
        Return the next frame from the socket.
        """
        fin, opcode, has_mask, length = decode_header(self._fobj)

        mask = self._read(4)

        if len(mask) != 4:
            raise exc.WebSocketError('Incomplete read while reading '
                                     'mask: %r' % (mask,))

        mask = struct.unpack('!BBBB', mask)

        if not length:
            return fin, opcode, ''

        payload = bytearray(self._read(length))

        if len(payload) != length:
            args = (length, len(payload))

            raise exc.WebSocketError('Incomplete read: expected message '
                                     'of %s bytes, got %s bytes' % args)

        for i in xrange(length):
            payload[i] = payload[i] ^ mask[i % 4]

        return fin, opcode, str(payload)

    def _read_message(self):
        """
        Return the next text or binary message from the socket.
        """
        opcode = None
        message = ''

        while True:
            fin, f_opcode, payload = self._read_frame()

            if f_opcode in (OPCODE_TEXT, OPCODE_BINARY):
                if opcode:
                    raise exc.ProtocolError('The opcode in non-fin frame is '
                                            'expected to be zero, got %r' % (
                                            f_opcode,))

                opcode = f_opcode
            elif not f_opcode:
                if not opcode:
                    raise exc.ProtocolError('Unexpected frame with opcode=0')
            elif f_opcode == OPCODE_CLOSE:
                if not payload:
                    raise ConnectionClosed(1000, None)

                if len(payload) < 2:
                    raise exc.ProtocolError('Invalid close frame: %r %r %r' % (
                        fin, f_opcode, payload))

                code = struct.unpack('!H', str(payload[:2]))[0]
                payload = payload[2:]

                if payload:
                    payload = self._decode_bytes(payload)

                raise ConnectionClosed(code, payload)

            elif f_opcode == OPCODE_PING:
                self.send_frame(payload, OPCODE_PONG)

                continue
            elif f_opcode == OPCODE_PONG:
                continue
            else:
                raise exc.ProtocolError("Unexpected opcode=%r" % (f_opcode,))

            message += payload

            if fin:
                break

        if opcode == OPCODE_TEXT:
            return message, False
        elif opcode == OPCODE_BINARY:
            return message, True

        raise RuntimeError('internal serror in gevent-websocket: opcode=%r' % (
            opcode,))

    def receive(self):
        try:
            result = self._read_message()
        except exc.ProtocolError:
            self.close(1002)

            raise
        except ConnectionClosed, e:
            self.close(e.code)

            return
        except:
            self.close(None)

            raise

        if not result:
            return

        message, is_binary = result

        if is_binary:
            return message

        return self._decode_bytes(message)

    def send_frame(self, message, opcode):
        """
        Send a frame over the websocket with message as its payload
        """
        if self.closed:
            raise exc.WebSocketError('The connection was closed')

        try:
            message = encode_bytes(message)

            self._write(encode_header(message, opcode) + message)
        except Exception:
            self.close(None)

            raise

    def send(self, message, binary=False):
        """
        Send a frame over the websocket with message as its payload
        """
        opcode = OPCODE_BINARY if binary else OPCODE_TEXT

        return self.send_frame(message, opcode)

    def close(self, code=1000, message=''):
        """
        Close the websocket, sending the specified code and message.

        Set `code` to None if you just want to sever the connection.
        """
        if self.closed:
            return

        if not code:
            super(WebSocketHybi, self).close()

            return

        try:
            message = encode_bytes(message)

            self.send_frame(
                struct.pack('!H%ds' % len(message), code, message),
                opcode=OPCODE_CLOSE)
        except exc.WebSocketError:
            # failed to write the closing frame but its ok because we're
            # closing the socket anyway.
            pass
        finally:
            super(WebSocketHybi, self).close()


def decode_header(stream):
    """
    Decode a Hybi header.

    :param stream: A file like object that can be 'read' from.
    :returns: A tuple containing fin, opcode, has_mask, length.
    """
    data = stream.read(2)

    if len(data) != 2:
        raise exc.WebSocketError('Unexpected EOF while decoding header')

    first_byte, second_byte = struct.unpack('!BB', data)

    if first_byte & HEADER_RSV_MASK:
        # one of the reserved bits is set, bail
        raise exc.ProtocolError(
            'Received frame with non-zero reserved bits: %r' % (data,))

    fin = first_byte & FIN_MASK == FIN_MASK
    opcode = first_byte & OPCODE_MASK
    has_mask = second_byte & MASK_MASK == MASK_MASK
    length = second_byte & LENGTH_MASK

    if opcode > 0x07:
        if fin == 0:
            raise exc.ProtocolError(
                'Received fragmented control frame: %r' % (data,))

        # Control frames MUST have a payload length of 125 bytes or less
        if length > 125:
            raise exc.FrameTooLargeException(
                'Control frame cannot be larger than 125 bytes: %r' % (data,))

    if length < 125:
        return fin, opcode, has_mask, length

    if length == 126:
        # 16 bit length
        data = stream.read(2)

        if len(data) != 2:
            raise exc.WebSocketError('Unexpected EOF while decoding header')

        length = struct.unpack('!H', data)[0]
    elif length == 127:
        # 64 bit length
        data = stream.read(8)

        if len(data) != 8:
            raise exc.WebSocketError('Unexpected EOF while decoding header')

        length = struct.unpack('!Q', data)[0]
    else:
        raise exc.ProtocolError('Malformed header %r' % (data,))

    return fin, opcode, has_mask, length


def encode_header(bytes, opcode):
    """
    Encodes a Hybi header.

    :param bytes: The payload of the header.
    :param opcode: The opcode of the header.
    :return: A bytestring encoded header.
    """
    header = chr(0x80 | opcode)
    msg_length = len(bytes)

    if msg_length < 126:
        header += chr(msg_length)
    elif msg_length < (1 << 16):
        header += '\x7e' + struct.pack('!H', msg_length)
    elif msg_length < (1 << 63):
        header += '\x7f' + struct.pack('!Q', msg_length)
    else:
        raise exc.FrameTooLargeException

    return header


def upgrade_connection(handler, environ):
    """
    Validate and 'upgrade' the HTTP request to a WebSocket request.

    If an upgrade succeeded then then handler will have `start_response` with a
    status of `101`, the environ will also be updated with `wsgi.websocket` and
    `wsgi.websocket_version` keys.

    :param handler: The WSGI handler providing the HTTP request context.
    :param environ: The HTTP environ dict.
    :return: The WSGI response iterator is something went awry.
    """
    version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")

    if version not in SUPPORTED_VERSIONS:
        msg = 'Unsupported WebSocket Version: %r' % (version,)

        handler.start_response('400 Bad Request', [
            ('Sec-WebSocket-Version', '13, 8, 7')
        ])

        return [msg]

    key = environ.get("HTTP_SEC_WEBSOCKET_KEY", '').strip()

    if not key:
        # 5.2.1 (3)
        msg = 'Sec-WebSocket-Key header is missing/empty'

        handler.start_response('400 Bad Request', [])

        return [msg]

    try:
        key_len = len(base64.b64decode(key))
    except TypeError:
        msg = 'Invalid key: %r' % (key,)

        handler.start_response('400 Bad Request', [])

        return [msg]

    if key_len != 16:
        # 5.2.1 (3)
        msg = 'Invalid key: %r' % (key,)

        handler.start_response('400 Bad Request', [])

        return [msg]

    environ.update({
        'wsgi.websocket': WebSocketHybi(handler.socket, environ),
        'wsgi.websocket_version': 'hybi-%s' % version
    })

    headers = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Accept", base64.b64encode(
            hashlib.sha1(key + GUID).digest())),
    ]

    handler.start_response("101 Switching Protocols", headers)
