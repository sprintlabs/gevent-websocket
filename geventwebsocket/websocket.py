__all__ = ['WebSocket', 'encode_bytes']


class WebSocket(object):
    """
    Base class for supporting websocket operations.

    :ivar environ: The http environment referenced by this connection.
    :ivar closed: Whether this connection is closed/closing.
    :ivar stream: The underlying file like object that will be read from /
        written to by this WebSocket object.
    """

    __slots__ = (
        'environ',
        'closed',
        'stream',
        'raw_write',
        'raw_read',
    )

    def __init__(self, environ, stream):
        self.environ = environ
        self.closed = False

        self.stream = stream

        self.raw_write = stream.write
        self.raw_read = stream.read

    def __del__(self):
        """
        This may or may not be called.
        """
        try:
            self.close()
        except:
            # close() may fail if __init__ didn't complete
            pass

    def close(self):
        """
        Called to close this connection. The underlying socket object is _not_
        closed, that is the responsibility of the initiator.
        """
        if self.closed:
            return

        self.closed = True

        self.stream = None
        self.raw_write = None
        self.raw_read = None

        self.environ = None

    @property
    def origin(self):
        if not self.environ:
            return

        return self.environ.get('HTTP_ORIGIN')

    @property
    def protocol(self):
        if not self.environ:
            return

        return self.environ.get('HTTP_SEC_WEBSOCKET_PROTOCOL')

    @property
    def version(self):
        if not self.environ:
            return

        return self.environ.get('HTTP_SEC_WEBSOCKET_VERSION')

    @property
    def path(self):
        if not self.environ:
            return

        return self.environ.get('PATH_INFO')


def encode_bytes(text):
    """
    :returns: The utf-8 byte string equivalent of `text`.
    """
    if isinstance(text, str):
        return text

    if not isinstance(text, unicode):
        text = unicode(text or '')

    return text.encode('utf-8')
