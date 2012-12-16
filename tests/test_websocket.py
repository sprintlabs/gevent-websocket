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

