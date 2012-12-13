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
        environ = self.environ
        upgrade = environ.get('HTTP_UPGRADE', '').lower()

        if upgrade == 'websocket':
            connection = environ.get('HTTP_CONNECTION', '').lower()

            if connection == 'upgrade':
                if not self.upgrade_websocket():
                    # the request was handled, probably with an error status
                    self.process_result()

                    return

        if not self.environ.get('wsgi.websocket'):
            # no websocket could be created and the connection was not upgraded
            super(WebSocketHandler, self).run_application()

            return

        self._write_with_headers(None)

        # from this point a valid websocket object is available in
        # self.environ['websocket']
        self.close_connection = True

        if hasattr(self, 'prevent_wsgi_call') and self.prevent_wsgi_call:
            return

        # since we're now a websocket connection, we don't care what the
        # application actually responds with for the http response
        self.application(self.environ, self._fake_start_response)

    def _fake_start_response(self, *args, **kwargs):
        pass

    def upgrade_websocket(self):
        result = None

        if self.environ.get('HTTP_SEC_WEBSOCKET_VERSION'):
            result = self._handle_hybi()
        elif self.environ.get('HTTP_ORIGIN'):
            result = self._handle_hixie()

        if self.status and not self.status.startswith('101 '):
            self.result = result or []

            return False

        return True

    def _handle_hybi(self):
        return hybi.upgrade_connection(self)

    def _handle_hixie(self):
        return hixie.upgrade_connection(self)


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
