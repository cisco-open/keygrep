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

import argparse
import logging
import pickle
import keychain


def main():
    """Search specified directories for SSH keys."""

    parser = argparse.ArgumentParser(description="""Searches the specified
    directories for SSH keys and writes a report and all discovered public and
    private keys to the output directory. Correlate public and private keys.
    """)

    parser.add_argument("--include_mangled", action="store_true",
                        help="""Include unrecovered "mangled" keys in results.
                        Without this option, keygrep will ignore discovered
                        private keys for which the following is true: 1. The
                        key is not encrypted; and 2. A fingerprint was unable
                        to be calculated. The keys that are included this way
                        may have been redacted or mangled (deliberately or not)
                        beyond keygrep's current parsing capabilities. They
                        might be recoverable by hand. Including this option may
                        result in invalid key files, so consider this when
                        feeding into tools like Driftwood.""")

    # Possible options to consider adding:
    # --only_encrypted (for cracking)
    # --only_unencrypted
    # --only_mangled (for developing the parser and identifying keys that need manual unmangling)

    parser.add_argument('-p', metavar='path', action='append', default=[],
                        help="""Add this path to the list of directories to
                        search for keys. May be used multiple times.""")

    parser.add_argument('-i', metavar='state_file', action='store', default='',
                        help="""Load the keychain object from this file and
                        write to it on close.""")

    parser.add_argument('-o', metavar='output_directory', action='store',
                        default='./findings', help="""Store extracted keys and
                        report in this directory, overwriting previous output
                        if any (default: %(default)s).""")

    parser.add_argument('-s', metavar='string', action='store', type=str,
                        default="", help="""Strip this leading string from the
                        reported key location paths (e.g., if you're searching
                        /tmp/inventory, you might set this to either /tmp or
                        /tmp/inventory.) Note that this operates on the path
                        only, not the filename. '~' will be expanded.""")

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s  - %(message)s")

    if args.i:
        try:
            with open(args.i, "rb") as inf:
                findings = pickle.load(inf)
        except FileNotFoundError:
            logging.info("No state file found, creating a new keychain...")
            findings = keychain.KeyChain(output_dir=args.o, path_prefix=args.s,
                                         include_mangled=args.include_mangled)
    else:
        findings = keychain.KeyChain(output_dir=args.o, path_prefix=args.s,
                                     include_mangled=args.include_mangled)

    try:
        for path in args.p:
            findings.load_private_keys(path)
            findings.load_public_keys(path)

    # If interrupted/exception, write whatever we have
    finally:
        logging.info("Correlating keys...")

        findings.correlate_keys()
        logging.info("Writing findings to %s", args.o)
        findings.write_summary()
        findings.write_private_keys()
        findings.write_public_keys()
        if args.i:
            with open(args.i, "wb") as outf:
                logging.info("Writing state to %s", args.i)
                pickle.dump(findings, outf)

if __name__ == "__main__":
    main()
