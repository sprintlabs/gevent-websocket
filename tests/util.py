"""
Test helpers.
"""

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO


class MockHandler(object):
    """
    A test compatible WSGI handler
    """

    def __init__(self, environ):
        self.environ = environ

    def log_error(self, msg):
        self.log = msg

    def start_response(self, status, headers):
        self.status = status
        self.headers = headers

    def write(self, data):
        self.socket.sendall(data)


class FakeFile(object):
    def __init__(self, socket, mode, buffersize):
        self.socket = socket
        self.mode = mode
        self.buffersize = buffersize

        self.closed = False

    def read(self, size):
        return self.socket.recv(size)

    def close(self):
        self.closed = True


class FakeSocket(object):
    """
    A fake socket like object that a `unittest.TestCase` can use to mock out
    the underlying intricacies of the real socket layer.
    """

    def __init__(self, data=''):
        self.data = data
        self._idx = 0

    def makefile(self, mode, buffersize):
        return FakeFile(self, mode, buffersize)

    def sendall(self, data):
        self.data += data

    def tell(self):
        return self._idx

    def recv(self, size):
        pos = self.tell()

        ret = self.data[pos:pos + size]
        self._idx += len(ret)

        return ret


class StreamStub(object):
    def __init__(self, data=None):
        self.read_stream = StringIO()
        self.write_stream = StringIO()
        self.closed = False

        if data:
            self.read_stream.write(data)
            self.read_stream.seek(0)

    def read(self, size):
        return self.read_stream.read(size)

    def write(self, data):
        self.write_stream.write(data)

    def close(self):
        self.closed = True

    def tell(self):
        return self.read_stream.tell()
