"""
Tests for `geventwebsocket.websocket`
"""

import unittest

from geventwebsocket import websocket


class EncodeBytesTestCase(unittest.TestCase):
    """
    Tests for `encode_bytes`
    """

    def test_string(self):
        """
        A simple byte string should be returned intact.
        """
        s = 'foobar'

        self.assertEqual(s, websocket.encode_bytes(s))

    def test_unicode(self):
        """
        A simple unicode object should be returned as a `utf-8` encoded
        byte string.
        """
        u = u'\u0192\xf8\xf8'
        s = u.encode('utf-8')

        self.assertEqual(s, websocket.encode_bytes(u))

    def test_non_string(self):
        """
        An object that acts like a string should be handled gracefully
        """
        class MyString(object):
            def __unicode__(self):
                return u'foobar'

        my_string = MyString()

        self.assertEqual('foobar', websocket.encode_bytes(my_string))

    def test_non_string_bytes(self):
        """
        An object that acts like a bytestring should return its bytes
        """
        class MyByteString(object):
            def __str__(self):
                return 'foobar'

        my_byte_string = MyByteString()

        self.assertEqual('foobar', websocket.encode_bytes(my_byte_string))

    def test_non_string_bad_utf8(self):
        """
        An object that acts like a bytestring but contains bad utf-8 data
        must raise a `UnicodeDecodeError` exception.
        """
        class MyBadUtf8(object):
            def __str__(self):
                return '\xff\x00'

        my_byte_string = MyBadUtf8()

        with self.assertRaises(UnicodeDecodeError) as ctx:
            websocket.encode_bytes(my_byte_string)


class WrappedReadTestCase(unittest.TestCase):
    """
    Tests for `websocket.wrapped_read`
    """

    def test_none_file_object(self):
        """
        Attempting to wrap a non file like object should raise an exception
        """
        obj = object()

        with self.assertRaises(TypeError) as ctx:
            websocket.wrapped_read(obj)

        exc = ctx.exception

        self.assertTrue(unicode(exc).startswith(
            'Expected file like object, received '))

    def test_non_callable_read(self):
        """
        A non callable read attrbute must raise a `TypeError`.
        """
        class MyFile(object):
            read = False

        with self.assertRaises(TypeError) as ctx:
            websocket.wrapped_read(MyFile())

        exc = ctx.exception

        self.assertTrue(unicode(exc).startswith(
            'Expected callable `read` for '))

    def test_args(self):
        """
        Args supplied to `wrapped_read` must be propagated to the read function
        """
        self.exectuted = False
        args = ('foo', 'bar')

        class MyFile(object):
            def read(myself, *myargs):
                self.assertEqual(args, myargs)
                self.executed = True

        reader = websocket.wrapped_read(MyFile())

        reader(*args)
        self.assertTrue(self.executed)

    def test_exception(self):
        """
        When a call to the underlying `read` raises an exception, an empty
        string must be returned.
        """
        self.executed = False

        class MyException(Exception):
            pass

        class MyFile(object):
            def read(myself):
                self.executed = True
                raise MyException

        reader = websocket.wrapped_read(MyFile())

        self.assertEqual('', reader())
        self.assertTrue(self.executed)

    def test_read(self):
        """
        Basic sanity check to ensure that reading from the file object works
        """
        class MyFile(object):
            def read(self):
                return 'foobar'

        reader = websocket.wrapped_read(MyFile())

        self.assertEqual('foobar', reader())


class FakeFile(object):
    def __init__(self, socket, mode, buffersize):
        self.socket = socket
        self.mode = mode
        self.buffersize = buffersize

        self.closed = False

    def read(self):
        pass

    def close(self):
        self.closed = True


class FakeSocket(object):
    """
    A fake socket like object that a `unittest.TestCase` can use to mock out
    the underlying intricacies of the real socket layer.
    """

    def makefile(self, mode, buffersize):
        return FakeFile(self, mode, buffersize)

    def sendall(self):
        pass


class WebSocketTestCase(unittest.TestCase):
    """
    Tests for `websocket.WebSocket`
    """

    def test_init(self):
        """
        Ensure the correct state when creating a WebSocket object.
        """
        socket = FakeSocket()
        environ = object()

        ws = websocket.WebSocket(socket, environ)

        self.assertIs(environ, ws.environ)
        self.assertFalse(ws.closed)

        fobj = ws._fobj

        self.assertIsInstance(fobj, FakeFile)
        self.assertIs(fobj.socket, socket)
        self.assertEqual(fobj.mode, 'rb')
        self.assertEqual(fobj.buffersize, 0)

    def test_close(self):
        """
        Ensure the correct state when closing a WebSocket object.
        """
        socket = FakeSocket()
        environ = object()

        ws = websocket.WebSocket(socket, environ)
        fobj = ws._fobj

        self.assertFalse(ws.closed)
        ws.close()

        self.assertTrue(ws.closed)
        self.assertIsNone(ws._socket)
        self.assertIsNone(ws._fobj)
        self.assertIsNone(ws._read)
        self.assertIsNone(ws._write)

        # Ensure that the file object was explicitly closed.
        self.assertTrue(fobj.closed)
