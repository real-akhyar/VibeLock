"""
VibeLock — Notifications Package
Slack and Microsoft Teams notification integration.
"""
from vibelock.src.notifications.dispatcher import dispatch_notification

__all__ = ["dispatch_notification"]