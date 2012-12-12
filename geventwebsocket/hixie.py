from .exceptions import WebSocketError
from .websocket import WebSocket, encode_bytes, wrapped_read


__all__ = ['WebSocketHixie']


class WebSocketHixie(WebSocket):
    def send(self, message):
        message = encode_bytes(message)

        with self._writelock:
            self._write("\x00" + message + "\xff")

    def _read_message(self, read):
        buf = ''

        while True:
            # TODO: reading 1 byte at a time is quite inefficient
            byte = read(1)

            if not byte:
                raise WebSocketError('Connection closed unexpectedly while '
                                     'reading message: %r' % (buf,))

            if byte == '\xff':
                return buf

            buf += byte

        return buf

    def receive(self):
        if not self.fobj:
            return

        read = wrapped_read(self.fobj)

        frame_type = read(1)

        if not frame_type:
            # whoops, something went wrong
            self.close()

            return

        if frame_type == '\x00':
            try:
                buf = self._read_message(read)
            except:
                self.close()

                raise

            # XXX - Why the replace?
            return buf.decode("utf-8", "replace")

        self.close()

        raise WebSocketError("Received an invalid frame_type=%r" % (
            ord(frame_type),))
