from gevent.pywsgi import WSGIHandler

from . import wsgi


class WebSocketHandler(WSGIHandler):
    """
    Automatically upgrades the connection to a websocket.

    To prevent the WebSocketHandler to call the underlying WSGI application,
    but only setup the WebSocket negotiations, do:

      mywebsockethandler.prevent_wsgi_call = True

    before calling run_application().  This is useful if you want to do more
    things before calling the app, and want to off-load the WebSocket
    negotiations to this library.  Socket.IO needs this for example, to send
    the 'ack' before yielding the control to your WSGI app.
    """

    @property
    def websocket(self):
        return self.environ.get('wsgi.websocket', None)

    def run_websocket(self):
        """
        Called when a websocket has been created successfully.
        """
        if hasattr(self, 'prevent_wsgi_call') and self.prevent_wsgi_call:
            return

        # since we're now a websocket connection, we don't care what the
        # application actually responds with for the http response
        try:
            self.application(self.environ, self._fake_start_response)
        finally:
            self.websocket.close()

    def get_environ(self):
        """
        There is a bug where the SERVER_PROTOCOL does not get set correctly.
        """
        env = super(WebSocketHandler, self).get_environ()

        if env.get('SERVER_PROTOCOL', '') != self.request_version:
            env['SERVER_PROTOCOL'] = self.request_version

        return env

    def run_application(self):
        """
        Attempt to create a websocket. If the request is not a WebSocket
        upgrade request, it will be passed to the application object.

        You probably don't want to override this function, see `run_websocket`.
        """
        self.result = wsgi.upgrade_websocket(
            self.environ,
            self.start_response,
            Stream(self)
        )

        if not self.websocket:
            # a websocket connection was not established
            if self.status:
                # A status was set, likely an error so just send the response
                if not self.result:
                    self.result = []

                self.process_result()

                return

            # this handler did not handle the request, so defer it to the
            # underlying application object
            return super(WebSocketHandler, self).run_application()

        if self.status and not self.headers_sent:
            self.write('')

        self.run_websocket()

    def _fake_start_response(self, status, headers):
        pass

    def start_response(self, status, headers, exc_info=None):
        """
        Called when the handler is ready to send a response back to the remote
        endpoint. A websocket connection may have not been created.
        """
        writer = super(WebSocketHandler, self).start_response(
            status, headers, exc_info=exc_info)

        assert not self.headers_sent

        if self.websocket:
            # so that `finalize_headers` doesn't write a Content-Length header
            self.provided_content_length = False
            # the websocket is now controlling the response
            self.response_use_chunked = False
            # once the request is over, the connection must be closed
            self.close_connection = True
            # prevents the Date header from being written
            self.provided_date = True

        return writer


class Stream(object):
    """
    Wraps the handler's socket/rfile attributes and makes it in to a file like
    object that can be read from/written to by the lower level websocket api.
    """

    __slots__ = (
        'handler',
        'read',
        'write'
    )

    def __init__(self, handler):
        self.handler = handler
        self.read = handler.rfile.read
        self.write = handler.socket.sendall
