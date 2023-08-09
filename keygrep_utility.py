"""Utility functions and classes"""

import os
import urllib
import urllib.parse
import re
import subprocess
import unicodedata


def squeeze(string, char):
    """Replace multiple consecutive instances of a character with a single
    one."""
    # https://stackoverflow.com/questions/42216559/fastest-way-to-deduplicate-contiguous-characters-in-string-python
    if string.find(char*2) != -1:
        return squeeze(string.replace(char*2, char), char)
    return string

def walk(path, func):
    """Run the given function against each file path discovered under the
    provided path."""
    for dirpath, dirnames, filenames in os.walk(path):
        for fname in filenames:
            if os.path.islink(os.path.join(dirpath, fname)):
                continue
            func(os.path.join(dirpath, fname))

def get_pubkey_data(path):
    """Return a tuple of the SHA256 and MD5 fingerprints of the file containing
    a single properly formatted public key at the givenpath. Returns (None,
    None) on failure."""

    try:
        sha256_fpr = subprocess.check_output(["ssh-keygen", "-l", "-f", path], stderr=subprocess.DEVNULL).strip()
        md5_fpr = subprocess.check_output(["ssh-keygen", "-E", "md5", "-l", "-f", path], stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        return (None, None)

    return (sha256_fpr.decode('utf-8'), md5_fpr.decode('utf-8'))

def get_key_data(path):
    """Return a tuple of the (SHA256 fingerprint, MD5 fingerprint, generated
    public key) of the file containing a single properly formatted private key
    at path that has permissions correctly set to 0600. If the key file is
    encrypted or not well-formed, returns (None, None, None)."""

    try:
        sha256_fpr = subprocess.check_output(["ssh-keygen", "-P", "", "-l", "-f", path], stderr=subprocess.DEVNULL).strip()
        md5_fpr = subprocess.check_output(["ssh-keygen", "-P", "", "-E", "md5", "-l", "-f", path], stderr=subprocess.DEVNULL).strip()
        pub = subprocess.check_output(["ssh-keygen", "-P", "", "-y", "-f", path], stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError:
        return (None, None, None)

    return (sha256_fpr.decode('utf-8'), md5_fpr.decode('utf-8'), pub.decode('utf-8'))

def remove_comment(key_string):
    """Remove comment from a public key."""
    if key_string.count(" ") < 2:
        return key_string
    return " ".join(key_string.split(" ")[0:2])

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
    with margin for use with incremented filenames in NumericOpen."""

    # URL decode
    name = recursive_decode(unsafe_name)

    name = unicodedata.normalize('NFKD', name)

    # Convert slashes into underscores
    name = re.sub(r'[/\\]', '_', name)

    # Convert whitespace into dashes
    name = re.sub(r'[\s]', '-', name)

    # Discard most characters
    name = re.sub(r'[^a-zA-Z0-9._-]', '', name)

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
                self.file_handle = open(os.path.join(self.path, self.target_name), **self.open_kwargs)
                break
            except FileExistsError:
                i += 1
                self.target_name = os.path.join(f"{basename}-{i}{ext}".format(basename, i, ext))

        return self.file_handle

    def __exit__(self, exception_type, exception_value, traceback):
        self.file_handle.close()
        subprocess.Popen(["chmod", "600", os.path.join(self.path, self.target_name)])
