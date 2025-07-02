#!/usr/bin/env python3
# Copyright 2023 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""Utility functions and classes"""

import os
import urllib
import urllib.parse
import re
import tempfile
import subprocess
import unicodedata
from functools import cache
import itertools
from pathlib import Path
from typing import Union, Optional, IO, Type, Dict, Callable, Any
from types import TracebackType


StrPath = Union[str, os.PathLike[str]]


def walk(path: StrPath, func: Callable[[StrPath], None]) -> None:
    """Runs the given function against each file discovered under the
    provided path."""

    # Follows symlinks pointing at regular files
    if Path(path).is_file():
        func(path)
    else:
        for dirpath, _, filenames in os.walk(path):
            for fname in filenames:
                if Path.is_symlink(Path(dirpath, fname)):
                    continue
                func(Path(dirpath, fname))

def get_privkey_data(privkey_string: str) -> Dict[str, Any]:
    """Returns a dict with the public key, fingerprint, encryption status, and
    a list of comment strings for the provided private key. If these cannot be
    determined, then the private key is either an encrypted PKCS8/PEM key, or
    is malformed. In either of these cases, the the public key returned will be
    None."""

    key_data: Dict[str, Any] = {"encrypted": False, "pub": None, "sha256": None, "comments": []}

    with tempfile.NamedTemporaryFile(mode="w") as key_file:
        key_file.write(privkey_string)
        key_file.flush()

        # Determine if it's encrypted
        keygen_process = subprocess.run(["ssh-keygen", "-P", "", "-y", "-f", key_file.name], capture_output=True, text=True, check=False)

        # ssh-keygen(1) doesn't provide informative return codes, so parse stderr (ew)
        if keygen_process.returncode == 0:
            key_data["pub"] = keygen_process.stdout
        elif "incorrect passphrase" in str(keygen_process.stderr).lower():
            key_data["encrypted"] = True

            # If the key is encrypted and is OpenSSH formatted (not PEM/PKCS8), we
            # can obtain the public key from it through a two-step conversion.

            # Export public key to RFC4716 format
            keygen_process = subprocess.run(["ssh-keygen", "-P", "", "-e", "-m",
                                             "RFC4716", "-f", key_file.name],
                                            capture_output=True, text=True, check=False)

            if keygen_process.returncode == 0:
                with tempfile.NamedTemporaryFile(mode="w") as ssh2_key_file:
                    ssh2_key_file.write(keygen_process.stdout)
                    ssh2_key_file.flush()
                    # Import public key to OpenSSH format
                    keygen_process = subprocess.run(["ssh-keygen", "-i", "-m", "RFC4716", "-f", ssh2_key_file.name], capture_output=True, text=True, check=False)
                    if keygen_process.returncode == 0:
                        key_data["pub"] = keygen_process.stdout

        keygen_process = subprocess.run(["ssh-keygen", "-l", "-f", key_file.name], capture_output=True, text=True, check=False)

        if keygen_process.returncode == 0:
            key_data["sha256"] = " ".join(keygen_process.stdout.split(" ")[1:2])
            comment = " ".join(keygen_process.stdout.split(" ")[2:-1])
            if comment not in ["", "no comment"]:
                key_data["comments"].append(comment)

    return key_data

def get_pubkey_data(pubkey_string: str) -> Dict[str, Optional[str]]:
    """Returns a dict with the SHA256 sum (without key size or comments) from
    the provided public key string."""

    key_data: Dict[str, Any] = {"sha256": None}

    with tempfile.NamedTemporaryFile(mode="w") as key_file:
        key_file.write(pubkey_string)
        key_file.flush()

        keygen_process = subprocess.run(["ssh-keygen", "-l", "-f", key_file.name], capture_output=True, text=True, check=False)
        if keygen_process.returncode == 0:
            key_data["sha256"] = " ".join(keygen_process.stdout.split(" ")[1:2])

    return key_data

@cache
def dsa_key_support() -> bool:
    """Return True if the system supports DSA keys. False otherwise."""

    ssh_process = subprocess.run(["ssh", "-Q", "key"], capture_output=True, text=True, check=True)

    return any(line.strip() == "ssh-dss" for line in ssh_process.stdout.splitlines())

def remove_path_prefix(path: StrPath, prefix: StrPath="") -> str:
    """Removes the prefix from the provided path if applicable. Returns a
    string so that the resulting object is JSON-serializable."""

    path, prefix = Path(path), Path(prefix)

    if path.is_relative_to(prefix):
        return str(path.relative_to(prefix))
    return str(path)

class NumericOpen():
    """Sanitizes the path "target_name" to a file name and writes it to the
    directory "path". Typical usage is that "target_name" is a directory tree,
    which is flattened into a single file. If the destination file exists,
    appends an ascending hyphenated numeric value to the name before writing
    it. Creates the directory "path" mode 0700 if it doesn't exist."""

    def __init__(self, target_name: StrPath, path: StrPath, encoding: str="utf-8"):
        self.path = Path(path)
        self.file_handle: Optional[IO[str]] = None
        self.encoding: str = encoding
        self.target_name: str = str(target_name)

    def __enter__(self) -> IO[str]:

        os.makedirs(self.path, mode=0o700, exist_ok=True)
        max_len = os.pathconf(self.path, "PC_NAME_MAX")
        sanitized_name = self._sanitize_filename(self.target_name)

        try:
            truncated_name = sanitized_name[0:max_len]
            fd = os.open(Path(self.path, truncated_name), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            self.file_handle = os.fdopen(fd, "w", encoding=self.encoding)
            return self.file_handle

        except FileExistsError:
            for i in itertools.count(start=2, step=1):
                try:
                    max_len = os.pathconf(self.path, "PC_NAME_MAX") - len(str(i)) - 1
                    truncated_name = sanitized_name[0:max_len] + "-" + str(i)
                    fd = os.open(Path(self.path, truncated_name), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                    self.file_handle = os.fdopen(fd, "w", encoding=self.encoding)
                    return self.file_handle
                except FileExistsError:
                    pass

        raise OSError

    def _sanitize_filename(self, target_name: str) -> str:
        """Sanitizes the input filename without truncating."""

        # URL decode
        name = self._recursive_decode(target_name)

        # Normalize
        name = unicodedata.normalize("NFKD", name)

        # Convert path separators into underscores
        name = name.replace("/", "_").replace("\\", "_")

        # Convert whitespace into hyphens
        name = re.sub(r"[\s]", "-", name)

        # Discard most characters
        name = re.sub(r"[^a-zA-Z0-9._-]", "", name)

        # Assign a default name if nothing left
        if name == "":
            name = "empty_name"

        return name

    def _recursive_decode(self, uri: str) -> str:
        """Apply urllib.parse.unquote to uri until it can't be decoded any
        further."""
        decoded = urllib.parse.unquote(uri)

        while decoded != uri:
            uri = decoded
            decoded = urllib.parse.unquote(uri)

        return decoded

    def __exit__(self, exception_type: Optional[Type[BaseException]],
                 exception_value: Optional[BaseException], traceback:
                 Optional[TracebackType]) -> None:
        if self.file_handle:
            self.file_handle.close()
