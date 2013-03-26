version_info = (0, 3, 6)
__version__ = ".".join(map(str, version_info))

__all__ = ['WebSocketHandler', 'WebSocketError', 'upgrade_websocket']

from .handler import WebSocketHandler
from .exceptions import WebSocketError
from .wsgi import upgrade_websocket
