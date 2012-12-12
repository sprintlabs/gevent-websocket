version_info = (0, 3, 6)
__version__ = ".".join(map(str, version_info))

__all__ = ['WebSocketHandler', 'WebSocketError']

from .handler import WebSocketHandler
from .exceptions import WebSocketError
