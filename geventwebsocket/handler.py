import urlparse

from gevent.pywsgi import WSGIHandler

from . import hybi
from . import hixie


class WebSocketHandler(WSGIHandler):
    """
    Automatically upgrades the connection to a websocket.

    To prevent the WebSocketHandler to call the underlying WSGI application,
    but only setup the WebSocket negotiations, do:

      mywebsockethandler.prevent_wsgi_call = True

    before calling handle_one_response().  This is useful if you want to do
    more things before calling the app, and want to off-load the WebSocket
    negotiations to this library.  Socket.IO needs this for example, to
    send the 'ack' before yielding the control to your WSGI app.
    """

    @property
    def ws_url(self):
        return reconstruct_url(self.environ)

    def run_application(self):
        upgrade = self.environ.get('HTTP_UPGRADE', '').lower()

        if upgrade == 'websocket':
            connection = self.environ.get('HTTP_CONNECTION', '').lower()

            if connection == 'upgrade':
                if not self.upgrade_websocket():
                    # the request was handled, probably with an error status
                    self.process_result()

                    return

        self.websocket = self.environ.get('wsgi.websocket')

        if not self.websocket:
            # no websocket could be created and the connection was not upgraded
            super(WebSocketHandler, self).run_application()

            return

        self.provided_content_length = True
        self.response_use_chunked = False
        self.close_connection = True

        self._write_with_headers(None)

        if hasattr(self, 'prevent_wsgi_call') and self.prevent_wsgi_call:
            return

        # since we're now a websocket connection, we don't care what the
        # application actually responds with for the http response
        self.application(self.environ, self._fake_start_response)

    def _fake_start_response(self, status, headers):
        pass

    def upgrade_websocket(self):
        """
        Attempt to upgrade the current environ into a websocket enabled
        connection.

        :returns: Whether the upgrade was successful.
        """
        # some basic sanity checks first
        if self.environ.get("REQUEST_METHOD") != "GET":
            self.start_response('400 Bad Request', [])

            return False

        if self.request_version != 'HTTP/1.1':
            self.start_response('400 Bad Request', [])

            return False

        result = None

        if self.environ.get('HTTP_SEC_WEBSOCKET_VERSION'):
            result = hybi.upgrade_connection(self)
        elif self.environ.get('HTTP_ORIGIN'):
            result = hixie.upgrade_connection(self)
        else:
            return False

        if self.status and not self.status.startswith('101 '):
            # could not upgrade the connection
            self.result = result or []

            return False

        return True


def reconstruct_url(environ):
    """
    Build a WebSocket url based on the supplied environ dict.

    Will return a url of the form:

        ws://host:port/path?query
    """
    secure = environ['wsgi.url_scheme'].lower() == 'https'

    if secure:
        scheme = 'wss://'
    else:
        scheme = 'ws://'

    host = environ.get('HTTP_HOST', None)

    if not host:
        host = environ['SERVER_NAME']

    port = None
    server_port = environ['SERVER_PORT']

    if secure:
        if server_port != '443':
            port = server_port
    else:
        if server_port != '80':
            port = server_port

    netloc = host

    if port:
        netloc = host + ':' + port

    path = environ.get('SCRIPT_NAME', '') + environ.get('PATH_INFO', '')

    query = environ['QUERY_STRING']

    return urlparse.urlunparse((
        scheme,
        netloc,
        path,
        '',  # params
        query,
        '',  # fragment
    ))
