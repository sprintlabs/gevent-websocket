import struct
import base64
import hashlib

from gevent import lock

from . import exceptions as exc
from .websocket import WebSocket, encode_bytes


__all__ = ['WebSocketHybi']


OPCODE_TEXT = 0x01
OPCODE_BINARY = 0x02
OPCODE_CLOSE = 0x08
OPCODE_PING = 0x09
OPCODE_PONG = 0x0a

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
    __slots__ = (
        '_readlock',
    )

    def __init__(self, socket, environ):
        super(WebSocketHybi, self).__init__(socket, environ)

        self._readlock = lock.Semaphore(1)

    def _decode_bytes(self, bytes):
        if not bytes:
            return bytes

        try:
            return bytes.decode('utf-8')
        except ValueError:
            self.close(1007)

            raise

    def _read_header(self):
        """
        Receive and decode a Hybi WebSocket header.

        As with all other private methods, if there is an error, no attempt will
        be made to clean up the socket.

        :returns: A tuple containing::
            fin: Whether the associated data with this header considers the
                frame complete.
            opcode: The message type.
            has_mask: Whether the payload contains mask data.
            length: The length of the payload.
        """
        data0 = self._read(2)

        if not data0:
            raise exc.WebSocketError('Peer closed connection unexpectedly')

        fin, opcode, has_mask, length = decode_header(data0)

        if not has_mask and length:
            raise exc.WebSocketError('Message from client is not masked')

        # In order to support larger messages sizes than 128, a special encoding
        # based on the length is used.

        if length < 126:
            # no more header to read
            return fin, opcode, has_mask, length

        if length == 126:
            # header is an extra 2 bytes
            data1 = self._read(2)

            if len(data1) != 2:
                raise exc.WebSocketError('Incomplete read while reading '
                                         '2-byte length: %r' % (data0 + data1,))

            length = struct.unpack('!H', data1)[0]
        else:
            # header is an extra 8 bytes
            assert length == 127, length

            data1 = self._read(8)

            if len(data1) != 8:
                raise exc.WebSocketError('Incomplete read while reading '
                                         '8-byte length: %r' % (data0 + data1,))

            length = struct.unpack('!Q', data1)[0]

        return fin, opcode, has_mask, length

    def _read_frame(self):
        """
        Return the next frame from the socket.
        """
        fin, opcode, has_mask, length = self._read_header()

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
            with self._readlock:
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
        # send frame is potentially called during close and self.socket may not
        # exist, so check self.fobj instead as that does not get cleaned up
        # until after.
        if not self.fobj:
            raise exc.WebSocketError('The connection was closed')

        with self._writelock:
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
        if not self.socket:
            # already closing/closed.
            return

        self.socket = None
        self._read = None

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


def decode_header(data):
    """
    Decode a Hybi header.

    :param data: A 2 byte string.
    :returns: A tuple containing fin, opcode, has_mask, length.
    """
    if len(data) != 2:
        raise ValueError

    first_byte, second_byte = struct.unpack('!BB', data)

    if first_byte & HEADER_RSV_MASK:
        # one of the reserved bits is set, bail
        raise exc.WebSocketError(
            'Received frame with non-zero reserved bits: %r' % (data,))

    fin = first_byte & 0x80 == 0x80
    opcode = first_byte & 0x0f

    if opcode > 0x07 and fin == 0:
        raise exc.WebSocketError('Received fragmented control frame: %r' % (
            data,))

    has_mask = second_byte & 0x80 == 0x80
    length = second_byte & 0x7f

    # Control frames MUST have a payload length of 125 bytes or less
    if opcode > 0x07 and length > 125:
        raise exc.FrameTooLargeException('Control frame payload cannot be'
                                         'larger than 125 bytes: %r' % (data,))

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


def upgrade_connection(handler):
    environ = handler.environ
    version = environ.get("HTTP_SEC_WEBSOCKET_VERSION")

    if version not in SUPPORTED_VERSIONS:
        msg = '400: Unsupported Version: %r' % (version,)

        handler.log_error(msg)
        handler.start_response('400 Unsupported Version', [
            ('Sec-WebSocket-Version', '13, 8, 7')
        ])

        return [msg]

    # check client handshake for validity
    if environ.get("REQUEST_METHOD") != "GET":
        # 5.2.1 (1)
        handler.start_response('400 Bad Request', [])

        return

    protocol, version = handler.request_version.split("/")

    if protocol != "HTTP":
        # 5.2.1 (1)
        handler.start_response('400 Bad Request', [])

        return

    try:
        version = float(version)
    except ValueError:
        handler.start_response('400 Bad Request', [])

        return

    if version < 1.1:
        # 5.2.1 (1)
        handler.start_response('400 Bad Request', [])

        return

    # XXX: nobody seems to set SERVER_NAME correctly. check the spec
    #if environ.get("HTTP_HOST") != environ.get("SERVER_NAME"):
    #    # 5.2.1 (2)
    #    handler.start_response('400 Bad Request', [])

    #    return

    key = environ.get("HTTP_SEC_WEBSOCKET_KEY")

    if not key:
        # 5.2.1 (3)
        msg = '400: Sec-WebSocket-Key header is missing/empty'

        handler.log_error(msg)
        handler.start_response('400 Bad Request', [])

        return [msg]

    if len(base64.b64decode(key)) != 16:
        # 5.2.1 (3)
        msg = '400: Invalid key: %r' % (key,)

        handler.log_error(msg)
        handler.start_response('400 Bad Request', [])

        return [msg]

    environ['wsgi.websocket'] = WebSocketHybi(handler.socket, environ)
    environ['wsgi.websocket_version'] = 'hybi-%s' % version

    headers = [
        ("Upgrade", "websocket"),
        ("Connection", "Upgrade"),
        ("Sec-WebSocket-Accept", base64.b64encode(
            hashlib.sha1(key + GUID).digest())),
    ]

    handler.start_response("101 Switching Protocols", headers)
