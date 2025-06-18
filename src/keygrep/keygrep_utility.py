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


def walk(path, func):
    """Runs the given function against each file discovered under the
    provided path."""

    # Follow symlinks if specifically provided
    if os.path.isfile(path):
        func(path)
    else:
        for dirpath, _, filenames in os.walk(path):
            for fname in filenames:
                if os.path.islink(os.path.join(dirpath, fname)):
                    continue
                func(os.path.join(dirpath, fname))

def get_privkey_data(privkey_string):
    """Returns a dict with the public key and encryption status of the provided
    private key. If these cannot be determined, then the private key is either
    an encrypted PKCS8/PEM key, or is malformed. In this case, the the public
    key returned will be None."""

    key_data = {"encrypted": False, "pub": None, "sha256": None, "comments": []}

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

def get_pubkey_data(pubkey_string):
    """Returns a dict with the SHA256 sum (without comments) from the provided
    public key string."""

    key_data = {"sha256": None}

    with tempfile.NamedTemporaryFile(mode="w") as key_file:
        key_file.write(pubkey_string)
        key_file.flush()

        keygen_process = subprocess.run(["ssh-keygen", "-l", "-f", key_file.name], capture_output=True, text=True, check=False)
        if keygen_process.returncode == 0:
            key_data["sha256"] = " ".join(keygen_process.stdout.split(" ")[1:2])

    return key_data

def remove_pubkey_comment(pubkey_string):
    """Returns the provided public key minus any comment string."""
    return " ".join(pubkey_string.split(" ")[0:2]).strip()

def recursive_decode(uri):
    """Apply urllib.parse.unquote to uri until it can't be decoded any
    further."""
    decoded = urllib.parse.unquote(uri)

    while decoded != uri:
        uri = decoded
        decoded = urllib.parse.unquote(uri)

    return decoded


def safe_filename(unsafe_name, max_len=255, safety_margin=12):
    """Sanitizes the input filename and truncates to a maximum length. Assumes a
    system filename length maximum of 255 and leaves an additional 12
    characters for incremented filenames (file-1.jpg, file-2.jpg, etc.) for use
    with incremented filenames in NumericOpen."""

    # URL decode
    name = recursive_decode(unsafe_name)

    name = unicodedata.normalize("NFKD", name)

    # Convert slashes into underscores
    name = re.sub(r"[/\\]", "_", name)

    # Convert whitespace into dashes
    name = re.sub(r"[\s]", "-", name)

    # Discard most characters
    name = re.sub(r"[^a-zA-Z0-9._-]", "", name)

    root, ext = os.path.splitext(name)

    # Truncate the part of the name before the extension
    root = root[0:max_len - safety_margin - len(ext)]
    safe_name = root + ext

    assert len(safe_name) <= (max_len - safety_margin)
    return safe_name

class NumericOpen():
    """Wrapper around open() with path. Creates the directory mode 0700 if it
    doesn't exist. Works similarly to tempfile.NamedTemporaryFile, but uses
    ascending numeric values instead of random strings."""

    def __init__(self, target_name, path, **kwargs):
        self.target_name = target_name
        self.path = path
        self.file_handle = None
        self.open_kwargs = kwargs

    def __enter__(self):
        os.makedirs(self.path, mode=0o700, exist_ok=True)
        self.target_name = safe_filename(self.target_name)
        basename = os.path.splitext(self.target_name)[0]
        ext = os.path.splitext(self.target_name)[1]

        i = 1

        # Could add a maximum increment value here
        while True:
            try:
                # Doesn't check to see if it ultimately succeeded
                self.file_handle = open(os.path.join(self.path, self.target_name), **self.open_kwargs, encoding="utf-8")
                break
            except FileExistsError:
                i += 1
                self.target_name = os.path.join(f"{basename}-{i}{ext}".format(basename, i, ext))

        return self.file_handle

    def __exit__(self, exception_type, exception_value, traceback):
        self.file_handle.close()
        os.chmod(os.path.join(self.path, self.target_name), 0o600)
