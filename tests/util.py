"""
Test helpers.
"""


class MockHandler(object):
    """
    A test compatible WSGI handler
    """

    def __init__(self, environ, request_version):
        self.environ = environ
        self.request_version = request_version

    def log_error(self, msg):
        self.log = msg

    def start_response(self, status, headers):
        self.status = status
        self.headers = headers


class FakeFile(object):
    def __init__(self, socket, mode, buffersize):
        self.socket = socket
        self.mode = mode
        self.buffersize = buffersize

        self.closed = False

    def read(self, size):
        pos = self.socket.tell()

        ret = self.socket.data[pos:pos + size]
        self.socket._idx += len(ret)

        return ret

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


