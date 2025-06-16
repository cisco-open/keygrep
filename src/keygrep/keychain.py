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
"""KeyChain class for Keygrep"""

import os
import re
import mmap
import json
import csv
import logging
import textwrap
from .keygrep_utility import walk, NumericOpen, get_pubkey_data, get_privkey_data, remove_pubkey_comment

__all__ = ["KeyChain"]

class KeyChain():
    """Class containing all discovered keys and derived information."""
    def __init__(self, output_dir="",  path_prefix="", include_mangled=False):

        self.private_keys = []
        self.public_keys = []
        self.output_dir = os.path.expanduser(output_dir)
        self.include_mangled = include_mangled

        # Strip this prefix from the found_in_path field
        # This makes sure it ends with a path separator
        self.path_prefix_pattern = re.compile(rf"^{os.path.join(os.path.normpath(os.path.expanduser(path_prefix)), '')}")

        self.private_key_pattern = re.compile(
            rb"-{5}BEGIN(.{1,12})PRIVATE KEY-{5}"
            rb"((?:(?!-{5}BEGIN).){,32768}?)"
            rb"-{5}END\1PRIVATE KEY-{5}",
            re.DOTALL
        )

        # OpenSSH formatted pubkey regex
        # Does not currently capture PEM/PKCS8 public keys
        # The following public key pattern does not attempt to capture ssh key
        # comments, as there's no foolproof way to identify the end of a
        # comment. The 68 character minimum length is the shortest length
        # likely to correspond to a valid key, which is an ed25519 public key.
        # Upper of limit of 3000 should be sufficient for up to 16384 bit keys

        # Longest key type identifier might be something like
        # sk-ecdsa-sha2-nistp521-cert-v01@openssh.com
        self.public_key_pattern = re.compile(
            rb"(sk\-)?"
            rb"(ssh|ecdsa)-[a-z0-9\.@\-]{0,80}"
            rb"\s+[a-zA-Z0-9+=/]{68,3000}"
        )

    def load_public_keys(self, path):
        """Walk path and search text files under it for public keys."""
        walk(os.path.expanduser(path), self.find_pubkeys_in_file)

    def load_private_keys(self, path):
        """Walk path and search text files under it for private keys."""
        walk(os.path.expanduser(path), self.find_privkeys_in_file)

    def write_summary(self):
        """Write a summary of private keys found"""
        os.makedirs(self.output_dir, mode=0o700, exist_ok=True)

        # Write public key JSON output
        with open(os.path.join(self.output_dir, "public.json"), "w", encoding="utf-8") as outf:
            outf.write(json.dumps(self.public_keys, indent=4))

        # Write private key JSON output
        with open(os.path.join(self.output_dir, "private.json"), "w", encoding="utf-8") as outf:
            outf.write(json.dumps(self.private_keys, indent=4))

        # Write private key CSV output
        with open(os.path.join(self.output_dir, "private.csv"), "w", encoding="utf-8") as outf:
            key_writer = csv.writer(outf, delimiter=",", quotechar='"', quoting=csv.QUOTE_MINIMAL)
            key_writer.writerow(["Encrypted", "sha256", "public key", "number of places private key found", "number of places public key found"])
            for key in self.private_keys:
                key_writer.writerow([key["encrypted"], key["sha256"], key["pub"], sum(len(k) for k in key["privkey_locations"].values()), sum(len(k) for k in key["pubkey_locations"].values())])

    def write_public_keys(self):
        """Dump public keys"""
        try:
            for filename in os.listdir(os.path.join(self.output_dir, "public")):
                os.unlink(os.path.join(self.output_dir, "public", filename))
        except FileNotFoundError:
            pass

        os.makedirs(os.path.join(self.output_dir, "public"), mode=0o700, exist_ok=True)

        for key in self.public_keys:
            # Use the lexically first filename where the key was found
            with NumericOpen(sorted(key["pubkey_locations"]\
                                            .keys())[0], os.path.join(\
                                            self.output_dir, "public"), mode="x") as key_out:
                key_out.write(key.get("pub"))

    def write_private_keys(self):
        """Dump private keys"""
        try:
            for filename in os.listdir(os.path.join(self.output_dir, "private")):
                os.unlink(os.path.join(self.output_dir, "private", filename))
        except FileNotFoundError:
            pass

        os.makedirs(os.path.join(self.output_dir, "private"), mode=0o700, exist_ok=True)

        for key in self.private_keys:
            # Use the lexically first filename where the key was found
            with NumericOpen(sorted(key["privkey_locations"].keys())[0], os.path.join(self.output_dir, "private"), mode="x") as key_out:
                key_out.write(key.get("priv"))

    def find_privkeys_in_file(self, path):
        """Find and parse all private keys in the file at path."""
        try:
            with open(path, "rb") as inf:
                try:
                    txt = mmap.mmap(inf.fileno(), 0, access=mmap.ACCESS_READ)
                    key_matches = re.finditer(self.private_key_pattern, txt)

                    for key_match in key_matches:
                        self.parse_private_key(key_match, path, key_match.start())

                # Zero length files
                except ValueError:
                    pass

        except IOError:
            logging.warning("IO error reading %s", path)

    def find_pubkeys_in_file(self, path):
        """Find and parse all public keys in the file at path."""
        try:
            with open(path, "rb") as inf:
                try:
                    txt = mmap.mmap(inf.fileno(), 0, access=mmap.ACCESS_READ)
                    key_matches = re.finditer(self.public_key_pattern, txt)
                    for key_match in key_matches:
                        self.parse_public_key(key_match.group(0).decode("utf-8"), path, key_match.start())
                except ValueError:
                    # Zero length files
                    pass

        except IOError:
            logging.warning("IO error reading %s", path)

    def parse_public_key(self, key, found_in_path, position=-1):
        """Parses a single public key block. Does not perform unmangling."""

        # Remove path prefix
        found_in_path = re.sub(self.path_prefix_pattern, "", found_in_path)

        key_data = {
            "pub": key,
            "sha256": None,
            "comments": [],
            "pubkey_locations": {found_in_path: [position]}
        }

        key_data.update(get_pubkey_data(key))

        # If we can't calculate the fingerprint, the key is mangled/invalid
        if not key_data["sha256"] and not self.include_mangled:
            return

        for index_existing_key,existing_key in enumerate(self.public_keys):

            # Compare based on SHA256 excluding any comments
            # public keys. If we can't determine the fingerprint (due to a mangled/invalid key),
            # treat it as unique unless it is string-identical to an existing key
            if (key_data["sha256"] == existing_key["sha256"] and key_data["sha256"] is not None) or key_data["pub"] == existing_key["pub"]:
                self.public_keys[index_existing_key]["pubkey_locations"].update({found_in_path: existing_key["pubkey_locations"].get(found_in_path, []) + [position]})

                # Remove duplicated positions from keys loaded a second time (from both a state file and a path)
                self.public_keys[index_existing_key]["pubkey_locations"][found_in_path] = sorted(list(set(self.public_keys[index_existing_key]["pubkey_locations"][found_in_path])))

                # There should only be at most one new comment in key_data, but the existing key may have multiple
                for comment in key_data["comments"]:
                    if comment not in self.public_keys[index_existing_key]["comments"]:
                        self.public_keys[index_existing_key]["comments"].append(comment)

                # No need to add a new key entry
                return

        self.public_keys.append(key_data)

    def parse_private_key(self, full_key, found_in_path, position=-1):
        """Parses a single key block. Performs fix-up transforms to restore
        mangled keys (e.g., when a private key found in an environment
        variable). Calculates fingerprints and appends a dictionary of the
        results to self.private_keys."""

        # inner_key is the interior of the -----BEGIN...----- and -----END...----- blocks
        inner_key = full_key.group(2).decode("utf-8")

        # Find and remove headers (Proc-Type, DEK-Info) if present from inner_key
        # We assume that even for mangled keys, these will end with a (possibly escaped) newline or
        # other non-escaped whitespace (typically a space), as with keys found in environment variables
        inner_key = inner_key.replace("\\n", "\n").replace("\\\n", "\n")
        headers = list(filter(None, re.findall(r"^|\s([a-zA-Z0-9,\-]+: [\S]+)", inner_key, flags=re.M)))
        inner_key = re.sub(r"^|\s[a-zA-Z0-9,\-]+: \S+", "", inner_key, flags=re.M).strip()

        # Special logic for viminfo
        inner_key = re.sub(r">\d+", "", inner_key)

        # Filter invalid characters
        inner_key = re.sub(r"[^a-zA-Z0-9/+=]", "", inner_key)

        # Standardize line length
        inner_key = "\n".join(textwrap.wrap(inner_key, width=64))

        affixes = (f"-----BEGIN{full_key.group(1).decode('utf-8')}PRIVATE KEY-----",
                   f"-----END{full_key.group(1).decode('utf-8')}PRIVATE KEY-----")

        # Re-insert headers with correct newlines
        if len(headers) > 0:
            key = "\n".join((affixes[0], "\n".join(headers) + "\n", inner_key, affixes[1])) + "\n"
        else:
            key = "\n".join((affixes[0], inner_key, affixes[1])) + "\n"

        mangled = False

        # Remove path prefix
        found_in_path = re.sub(self.path_prefix_pattern, "", found_in_path)

        key_data = {
            "encrypted": False,
            "sha256": None,
            "comments": [],
            "priv": key,
            "pub": None,
            "privkey_locations": {found_in_path: [position]},
            "pubkey_locations": {},
        }

        key_data.update(get_privkey_data(key))

        # The key is mangled beyond automatic repair
        if not key_data["pub"] and not key_data["encrypted"]:
            mangled = True

        if not mangled and not key_data["encrypted"]:
            logging.info("Found key of length %d at position %d in %s", len(key), position, found_in_path)
        elif not mangled:
            logging.info("Found encrypted key of length %d at position %d in %s", len(key), position, found_in_path)
        else:
            logging.info("Found mangled key of length %d at position %d in %s", len(key), position, found_in_path)

        if mangled and not self.include_mangled:
            return

        for index_existing_key,existing_key in enumerate(self.private_keys):

            # Compare based on SHA256 excluding any comments
            # If we can't determine the fingerprint (due to mangled/invalid keys, or encrypted PEM/PKCS8 keys),
			# treat the key as unique unless it is string-identical to an existing key
            if (key_data["sha256"] == existing_key["sha256"] and key_data["sha256"] is not None) or key_data["priv"] == existing_key["priv"]:

                # If this is a duplicate key, update the original to include where we found the copy and any new comment
                self.private_keys[index_existing_key]["privkey_locations"].update({found_in_path: existing_key["privkey_locations"].get(found_in_path, []) + [position]})

                # There should only be at most one new comment in key_data, but the existing key may have multiple
                for comment in key_data["comments"]:
                    if comment not in self.private_keys[index_existing_key]["comments"]:
                        self.private_keys[index_existing_key]["comments"].append(comment)

                # Remove duplicated positions from keys loaded a second time (from both a state file and a path)
                self.private_keys[index_existing_key]["privkey_locations"]\
                    [found_in_path] = sorted(list(set(self.private_keys\
                    [index_existing_key]["privkey_locations"][found_in_path])))

                # No need to add a new key entry
                return

        self.private_keys.append(key_data)

    def correlate_keys(self):
        """Compare discovered public and private keys."""

        for pubkey in self.public_keys:
            for index_privkey,privkey in enumerate(self.private_keys):
                if privkey["pub"] is not None:
                    if remove_pubkey_comment(privkey["pub"]) == remove_pubkey_comment(pubkey["pub"]):
                        self.private_keys[index_privkey]["pubkey_locations"] = pubkey["pubkey_locations"]

                # Unique the discovered public key locations, or each
                # "instance" of a private key will result in a duplicate entry
                for path, offset in self.private_keys[index_privkey]["pubkey_locations"].items():
                    self.private_keys[index_privkey]["pubkey_locations"][path] = sorted(list(set(offset)))
