"""
Searches the specified directories for public and private SSH keys, correlates them, and writes a report and all discovered keys to the output directory.
"""
from .keychain import KeyChain

__all__ = ["KeyChain"]
