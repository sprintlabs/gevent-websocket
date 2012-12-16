from gevent import lock


__all__ = ['WebSocket', 'encode_bytes', 'wrapped_read']


class WebSocket(object):
    __slots__ = (
        'environ',
        'socket',
        'fobj',
        '_writelock',
        '_write',
        '_read',
        'closed'
    )

    def __init__(self, socket, environ, lock_class=lock.Semaphore):
        self.environ = environ
        self.socket = socket
        self.closed = False

        self.fobj = socket.makefile('rb', 0)
        self._writelock = lock_class(1)
        self._write = socket.sendall
        self._read = wrapped_read(self.fobj)

    def close(self):
        """
        Close the fobj but not the socket, that is the responsibility of the
        initiator.
        """
        if not self.socket:
            return

        self.socket = None
        self.closed = True

        try:
            self.fobj.close()
        except:
            # TODO: Think about logging?
            pass

        self.fobj = None
        self._write = None

    @property
    def origin(self):
        return self.environ.get('HTTP_ORIGIN')

    @property
    def protocol(self):
        return self.environ.get('HTTP_SEC_WEBSOCKET_PROTOCOL')

    @property
    def version(self):
        return self.environ.get('HTTP_SEC_WEBSOCKET_VERSION')

    @property
    def path(self):
        return self.environ.get('PATH_INFO')


def encode_bytes(text):
    """
    :returns: The utf-8 byte string equivalent of `text`.
    """
    if isinstance(text, str):
        return text

    if not isinstance(text, unicode):
        text = unicode(text)

    return text.encode('utf-8')


def wrapped_read(fobj):
    """
    Returns a callable that will return an empty string if reading from the fobj
    fails for _any_ reason.

    `fobj` in this case is a file like object e.g. `socket.makefile()`
    """
    # basic sanity check
    if not hasattr(fobj, 'read'):
        raise TypeError('Expected file like object, received %r' % (fobj,))

    read = fobj.read

    if not callable(read):
        raise TypeError('Expected callable `read` for %r' % (fobj,))

    def reader(*args):
        try:
            return read(*args)
        except:
            return ''

    return reader
