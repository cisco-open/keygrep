"""Types for Keygrep"""

import os
from typing import Union, Optional, TypedDict

StrPath = Union[str, os.PathLike[str]]

class PublicKeyRecord(TypedDict):
    """Keychain entry for a public key"""
    pub: str
    sha256: Optional[str]
    comments: list[str]
    pubkey_locations: dict[str, list[int]]

class PrivateKeyRecord(TypedDict):
    """Keychain entry for a private key"""
    encrypted: bool
    pub: Optional[str]
    sha256: Optional[str]
    comments: list[str]
    priv: str
    pubkey_locations: dict[str, list[int]]
    privkey_locations: dict[str, list[int]]
