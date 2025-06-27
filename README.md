# Keygrep

## Red team oriented key finder and correlator

Keygrep is a tool for searching and correlating ssh keys from text files in
directory trees.  It can recover keys that appear in "mangled" formats, such as
environment variables, .viminfo, and config files. It does not perform binary
unpacking or cracking.

```
$ keygrep -h

usage: keygrep [-h] [--include_mangled] [-p path] [-i state_file] [-s string] output_directory

Searches the specified directories for public and private SSH keys, correlates them, and writes a report and all discovered keys to the output directory.

positional arguments:
  output_directory   Store extracted keys and report in this directory, overwriting previous output if any.

options:
  -h, --help         show this help message and exit
  --include_mangled  Include unrecovered "mangled" keys in results. Without this option, keygrep will log and ignore potentially recoverable public and private keys
                     that it discovers. Sometimes these are redacted or malformed example keys (such as in docs), but they might be recoverable by hand.
                     Including this option may result in invalid key files.
  -p path            Add this to the list of paths to search for keys. May be used multiple times.
  -i state_file      Load public and private keys from this JSON state file if it exists and write to it on close.
  -s string          Strip this leading string from the reported key location paths (e.g., if you're searching /tmp/inventory, you might set this to either /tmp or /tmp/inventory.) Note that this operates on the path only, not the filename. '~' will be expanded.
```

### Installation
Keygrep has no Python dependencies, but OpenSSH must be installed, as it makes
external calls to `ssh-keygen`. Install Keygrep by cloning this repository and
running `pip install .` from it.

DSA key support is disabled by default in OpenSSH 9.8/9.8p1 (and removed in
OpenSSH 10.0/10.0p2). If this version is installed, DSA keys will still be
discovered, but are logged as unrecoverable ("mangled") keys.

### Usage:
Search the `/sample-data` directory for keys and write the output to `findings/`:

```
$ keygrep -p /sample-data findings
2025-06-02 19:46:04,845 - INFO  - Found key of length 1801 at position 590 in /sample-data/ps_snippet.txt
2025-06-02 19:46:04,922 - INFO  - Found key of length 227 at position 0 in /sample-data/plain/ecdsa_pem
2025-06-02 19:46:04,949 - INFO  - Found mangled key of length 82 at position 0 in /sample-data/plain/redacted_key
2025-06-02 19:46:04,977 - INFO  - Found key of length 400 at position 0 in /sample-data/plain/ed25519
2025-06-02 19:46:05,007 - INFO  - Found key of length 1801 at position 474 in /sample-data/homedirs/jbloggs/.viminfo
2025-06-02 19:46:05,015 - INFO  - Found key of length 1801 at position 2326 in /sample-data/homedirs/jbloggs/.viminfo
2025-06-02 19:46:05,032 - INFO  - Found key of length 1801 at position 1 in /sample-data/homedirs/jbloggs/tf.key
2025-06-02 19:46:05,225 - INFO  - Correlating keys...
2025-06-02 19:46:05,225 - INFO  - Writing findings to ./findings
```

This generates several files under `findings`, of which `private.json` is the
most important. This contains a list of JSON objects, each corresponding to a
unique private key. The structure looks like this:

```json
    {
        "encrypted": false,
        "sha256": "SHA256:REoRXyGCovWtM87Lb/xUl3MaJQlPqB7SFLmqOBVtQ+k",
        "comments": [
            "server key",
            "jbloggs@workstation-7"
        ],
        "priv": "-----BEGIN OPENSSH PRIVATE KEY-----...-----END OPENSSH PRIVATE KEY-----\n",
        "pub": "ssh-rsa ...",
        "privkey_locations": {
            "/sample-data/ps_snippet.txt": [
                590
            ],
            "/sample-data/homes/jbloggs/.ssh/key": [
                0
            ]
        },
        "pubkey_locations": {
            "/sample-data/configs/terraform.tfvars.json": [
                831
            ],
            "/sample-data/homes/jbloggs/.ssh/key.pub": [
                0
            ]
        }
    }
```

From this, we could guess that the key found in the output of a ps command (in
an environment variable) might get us into the host defined in
`terraform.tfvars.json`. Each unique comment associated with the private key is
also stored. Public key comments are not captured, due to the lack of a way to
identify the end of a comment in keys contained in unstructured data.

The "encrypted" field identifies whether Keygrep found any cleartext copies of a
particular key. In the case where both encrypted and cleartext versions of a
key are discovered, this value will be false, and Keygrep will store the
cleartext version. If only encrypted copies are discovered, the value will be
true.

Other than this exception, Keygrep stores the first version of each key it
finds.

[jq](https://jqlang.github.io/jq/) is recommended for parsing
private.json. For example, you might want to list only the discovered
private keys for which public keys were also discovered:
```
jq -r '.[] | select(.pubkey_locations | length > 0) | {sha256: .sha256, pubkey_locations: .pubkey_locations, privkey_locations: .privkey_locations}' < findings/private.json
```

This will produce more compact output that looks something like this:

```json
{
  "sha256": "SHA256:REoRXyGCovWtM87Lb/xUl3MaJQlPqB7SFLmqOBVtQ+k",
  "pubkey_locations": {
    "/sample-data/homes/jbloggs/.ssh/key.pub": [
      0
    ],
    "/sample-data/configs/terraform.tfvars.json": [
      831
    ]
  },
```

Each discovered public key is also recorded in `public.json`.

For convenience, the private and public keys are also stored in individual
files under `private/` and `public/` in the output directory.

### Development
Simply install and run `nox` to lint, test, and build.
