from socket import error as socket_error


class WebSocketError(socket_error):
    """
    Base class for all websocket errors.
    """


class FrameTooLargeException(WebSocketError):
    """
    Raised if a frame is received that is too large.
    """
