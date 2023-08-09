import os
import re
import mmap
import tempfile
import subprocess
import json
import csv
import logging
import keygrep_utility

class KeyChain():
    """Class containing all discovered keys and derived information."""
    def __init__(self, output_dir="findings", path_prefix="", include_mangled=False):

        self.private_keys = []
        self.public_keys = []
        self.output_dir = os.path.expanduser(output_dir)
        self.include_mangled = include_mangled

        # Strip this prefix from the found_in_path field
        # This makes sure it ends with a path separator
        self.path_prefix_pattern = re.compile(r"^{}".format(os.path.join(os.path.normpath(os.path.expanduser(path_prefix)), "")))

        # Broadest working definition of "potentially mangled but seemingly complete private key"
        self.private_key_pattern = re.compile(r"-{5}BEGIN(.{1,12})PRIVATE KEY-{5}.{,32768}?-{5}END\1PRIVATE KEY-{5}".encode("utf-8"), re.DOTALL)

        # The following public key pattern does not attempt to capture ssh key
        # comments, as there's no foolproof way to identify the end of a
        # comment. The 68 character minimum length is the shortest length
        # likely to correspond to a valid key, which is an ed25519 public key.
        self.public_key_pattern = re.compile(r"ssh-[a-z0-9]{0,7}\s+[a-zA-Z0-9+=/]{68,}".encode("utf-8"))

    def load_public_keys(self, path):
        """Walk path and search text files under it for public keys."""
        keygrep_utility.walk(os.path.expanduser(path), self.find_pubkeys_in_file)

    def load_private_keys(self, path):
        """Walk path and search text files under it for private keys."""
        keygrep_utility.walk(os.path.expanduser(path), self.find_privkeys_in_file)

    def write_summary(self):
        """Write a summary of private keys found"""
        os.makedirs(self.output_dir, mode=0o700, exist_ok=True)

        # Write public key JSON output
        with open(os.path.join(self.output_dir, "public.json"), "w") as outf:
            outf.write(json.dumps(self.public_keys, indent=4))

        # Write private key JSON output
        with open(os.path.join(self.output_dir, "private.json"), "w") as outf:
            outf.write(json.dumps(self.private_keys, indent=4))

        # Write private key CSV output
        with open(os.path.join(self.output_dir, "private.csv"), "w") as outf:
            key_writer = csv.writer(outf, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            key_writer.writerow(["Encrypted", "sha256", "md5", "public key", "number of places private key found", "number of places public key found"])
            for key in self.private_keys:
                key_writer.writerow([key['encrypted'], key['sha256'], key['md5'], key['pub'], sum(len(k) for k in key['privkey_locations'].values()), sum(len(k) for k in key['pubkey_locations'].values())])

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
            with keygrep_utility.NumericOpen(sorted(key['pubkey_locations'].keys())[0], os.path.join(self.output_dir, "public"), mode="x") as key_out:
                key_out.write(key.get('pub'))
                key_out.write("\n")

    def write_private_keys(self):
        """Dump private keys"""

        try:
            for filename in os.listdir(os.path.join(self.output_dir, "private")):
                os.unlink(os.path.join(self.output_dir, "private", filename))
        except FileNotFoundError:
            pass

        os.makedirs(self.output_dir, mode=0o700, exist_ok=True)

        for key in self.private_keys:
            # Use the lexically first filename where the key was found
            with keygrep_utility.NumericOpen(sorted(key['privkey_locations'].keys())[0], os.path.join(self.output_dir, "private"), mode="x") as key_out:
                key_out.write(key.get('priv'))
                key_out.write("\n")

    def find_privkeys_in_file(self, path):
        """Find and parse all private keys in the file at path."""
        try:
            with open(path, 'rb') as inf:
                try:
                    txt = mmap.mmap(inf.fileno(), 0, access=mmap.ACCESS_READ)
                    key_matches = re.finditer(self.private_key_pattern, txt)

                    for key_match in key_matches:
                        self.parse_private_key(key_match.group(0).decode("utf-8"), path, key_match.start())

                # Zero length files
                except ValueError:
                    pass

        except IOError:
            logging.warning("IO error reading %s", path)

    def find_pubkeys_in_file(self, path):
        """Find and parse all public keys in the file at path."""
        try:
            with open(path, 'rb') as inf:
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
        """Parses a single public key block."""

        with tempfile.NamedTemporaryFile(mode='w') as key_file:
            key_file.write(key)
            key_file.flush()
            if os.stat(key_file.name).st_size == 0:
                logging.warning("Trying to parse an empty key file from %s", found_in_path)
            # Validate the key
            if keygrep_utility.get_pubkey_data(key_file.name) == (None, None):
                return

        # Remove path prefix
        found_in_path = re.sub(self.path_prefix_pattern, "", found_in_path)

        for index_existing_key,existing_key in enumerate(self.public_keys):
            if key == existing_key['pub']:
                self.public_keys[index_existing_key]["pubkey_locations"].update({found_in_path: existing_key["pubkey_locations"].get(found_in_path, []) + [position]})
                # Remove duplicated positions from keys loaded a second time (from
                # both a state file and a path)
                self.public_keys[index_existing_key]["pubkey_locations"][found_in_path] = sorted(list(set(self.public_keys[index_existing_key]["pubkey_locations"][found_in_path])))

                # Since we found this key already, bail out instead of
                # appending a duplicate key
                return

        key_data = {'pub': key, 'pubkey_locations': {found_in_path: [position]}}

        self.public_keys.append(key_data)

    def parse_private_key(self, key, found_in_path, position=-1):
        """Parses a single key block. Performs fix-up transforms to restore
        mangled keys (e.g., when a private key found in an environment
        variable). Calculates fingerprints and appends a dictionary of the
        results to self.private_keys."""

        key = key.replace("\\n", "\n")
        splitkey = key.split("-----")
        # Convert spaces to new lines for keys dumped from environment variables
        splitkey[2] = splitkey[2].replace(" ", "\n")

        # Re-insert newlines in encrypted, PEM format key headers.
        # At this point DEK-Info if present still needs repair
        splitkey[2] = re.sub(":\n", ": ", splitkey[2])

        key = "-----".join(splitkey)

        # Remove invalid characters.
        # This method doesn't eliminate '-' characters inside of the key block
        key = re.sub(r'[^a-zA-Z0-9\-/+=\s,:]', '', key)
        key = key.replace("\t", "")
        key = keygrep_utility.squeeze(key, "\n")

        # Two newlines expected after DEK-Info
        key = re.sub("^(DEK-Info.+?)$", r"\1\n", key, count=1, flags=re.M)

        key = key.strip() + "\n"
        found_in_path = re.sub(self.path_prefix_pattern, "", found_in_path)

        logging.info("Found key of length %d in %s at position %d", len(key), found_in_path, position)

        with tempfile.NamedTemporaryFile(mode='w') as key_file:
            key_file.write(key)
            key_file.flush()
            if os.stat(key_file.name).st_size == 0:
                logging.warning("Trying to parse an empty key file from %s", found_in_path)

            fprs = keygrep_utility.get_key_data(key_file.name)

            # Try to generate a public key from the private key temporary file using an empty passphrase
            # If this fails, the key is either encrypted or malformed
            # Note that ssh-keygen may also check "key.pub" if you ask it for the
            # fingerprint of the encrypted key "key".
            # What if the key really was encrypted with an empty passphrase?
            encrypted = False

            keygen_process = subprocess.run(["ssh-keygen", "-P", "", "-y", "-f", key_file.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            # ssh-keygen(1) doesn't provide informative return codes, so parse stderr (ew)
            if "incorrect passphrase" in str(keygen_process.stderr):
                encrypted = True
                logging.warning("Key found at position %d in %s is encrypted", position, found_in_path)
            elif keygen_process.returncode != 0:
                logging.warning("Key found at position %d in %s is mangled", position, found_in_path)

        # If the key is not encrypted but we haven't determined the
        # fingerprint, it's mangled
        if not self.include_mangled:
            if encrypted is False and not fprs[0]:
                return True

        for index_existing_key,existing_key in enumerate(self.private_keys):
            if key == existing_key['priv']:

                # If this is a duplicate key, update the original to include where we found the copy
                self.private_keys[index_existing_key]["privkey_locations"].update({found_in_path: existing_key["privkey_locations"].get(found_in_path, []) + [position]})
                # Remove duplicated positions from keys loaded a second time (from
                # both a state file and a path)
                self.private_keys[index_existing_key]["privkey_locations"][found_in_path] = sorted(list(set(self.private_keys[index_existing_key]["privkey_locations"][found_in_path])))

                # Since we found this key already, bail out instead of
                # appending a duplicate key
                return True

        # "pubkey_locations" unknown until correlate_keys()
        key_data = {'encrypted': encrypted, 'sha256': fprs[0], 'md5': fprs[1], 'priv': key, 'pub': fprs[2], 'privkey_locations': {found_in_path: [position]}, 'pubkey_locations': {}}

        self.private_keys.append(key_data)
        return True

    def correlate_keys(self):
        """Compare discovered public and private keys."""

        for pubkey in self.public_keys:
            for index_privkey,privkey in enumerate(self.private_keys):
                if privkey['pub'] is not None:
                    if keygrep_utility.remove_comment(privkey['pub'].strip()) == keygrep_utility.remove_comment(pubkey['pub'].strip()):
                        self.private_keys[index_privkey]["pubkey_locations"] = pubkey["pubkey_locations"]

                # Unique the discovered public key locations, or each
                # "instance" of a private key will result in a duplicate entry
                for k, v in self.private_keys[index_privkey]["pubkey_locations"].items():
                    self.private_keys[index_privkey]["pubkey_locations"][k] = sorted(list(set(v)))
