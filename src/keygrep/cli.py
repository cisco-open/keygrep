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
"""Discovers and compares ssh keys"""

import sys
import json
import argparse
import logging
from pathlib import Path
from keygrep.keychain import KeyChain


def main() -> None:
    """Search specified directories for SSH keys."""

    parser = argparse.ArgumentParser(description="""Searches the specified
    directories for public and private SSH keys, correlates them, and writes a
    report and all discovered keys to the output directory.""")

    parser.add_argument("--include_mangled", action="store_true",
                        help="""Include unrecovered "mangled" keys in results.
                        Without this option, keygrep will log and ignore
                        potentially recoverable public and private keys that it
                        discovers.  Sometimes these are redacted or malformed
                        example keys (such as in docs), but they might be
                        recoverable by hand. Including this option may result
                        in invalid key files.""")

    # Possible options to consider adding:
    # --only_encrypted (for cracking)
    # --only_unencrypted
    # --only_mangled (for developing the parser and identifying keys that need manual unmangling)

    parser.add_argument("-p", metavar="path", action="append", default=[],
                        help="""Add this to the list of paths to search for
                        keys. May be used multiple times.""")

    parser.add_argument("-i", metavar="state_file", action="store", default="",
                        help="""Load public and private keys from this JSON
                        state file if it exists and write to it on close.""")

    parser.add_argument(metavar="output_directory", dest="out_dir", action="store",
                        help="""Store extracted keys and
                        report in this directory, overwriting previous output
                        if any.""")

    parser.add_argument("-s", metavar="string", action="store", type=str,
                        default="", help="""Strip this leading string from the
                        reported key location paths (e.g., if you're searching
                        /tmp/inventory, you might set this to either /tmp or
                        /tmp/inventory.) Note that this operates on the path
                        only, not the filename. '~' will be expanded.""")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s  - %(message)s")

    findings = KeyChain(output_dir=args.out_dir, path_prefix=args.s,
                        include_mangled=args.include_mangled)

    if args.i:
        try:
            findings.read_state(args.i)
        except (json.decoder.JSONDecodeError, IOError, KeyError, UnicodeDecodeError):
            sys.exit(1)

    try:
        for path in args.p:
            if not Path(path).exists():
                logging.warning("Path %s does not exist", path)
            findings.load_private_keys(path)
            findings.load_public_keys(path)

    # If interrupted/exception, write whatever we have
    finally:
        logging.info("Correlating keys...")

        findings.correlate_keys()
        logging.info("Writing findings to %s", args.out_dir)
        findings.write_summary()
        findings.write_private_keys()
        findings.write_public_keys()
        if args.i:
            try:
                findings.write_state(args.i)
            except IOError:
                sys.exit(1)

if __name__ == "__main__":
    main()
