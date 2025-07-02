"""Types for Keygrep"""

import os
from typing import Union, List, Dict, Optional, TypedDict

StrPath = Union[str, os.PathLike[str]]

class PublicKeyRecord(TypedDict):
    """Keychain entry for a public key"""
    pub: str
    sha256: Optional[str]
    comments: List[str]
    pubkey_locations: Dict[str, List[int]]

class PrivateKeyRecord(TypedDict):
    """Keychain entry for a private key"""
    encrypted: bool
    pub: Optional[str]
    sha256: Optional[str]
    comments: List[str]
    priv: str
    pubkey_locations: Dict[str, List[int]]
    privkey_locations: Dict[str, List[int]]
