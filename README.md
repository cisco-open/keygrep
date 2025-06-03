# Keygrep

## Red team oriented key finder and correlator

Keygrep is a tool for searching and correlating ssh keys from text files in
directory trees.  It can recover keys that appear in "mangled" formats, such as
ps environment variables, .viminfo, and config files. It does not perform any
unpacking or cracking.

```
$ ./__init__.py -h

usage: __init__.py [-h] [--include_mangled] [-p path] [-i state_file] [-o output_directory] [-s string]

Searches the specified paths for public and private SSH keys, correlates them, and writes a report and all
discovered keys to the output directory.

optional arguments:
  -h, --help           show this help message and exit
  --include_mangled    Include unrecovered "mangled" keys in results. Without this option, keygrep will
                       ignore discovered private keys for which the following is true: 1. The key is not
                       encrypted; and 2. A fingerprint was unable to be calculated. The keys that are
                       included this way may have been redacted or mangled (deliberately or not) beyond
                       keygrep's current parsing capabilities. They might be recoverable by hand. Including
                       this option may result in invalid key files.
  -p path              Add this to the list of paths to search for keys. May be used multiple times.
  -i state_file        Load the keychain object from this file and write to it on close.
  -o output_directory  Store extracted keys and report in this directory, overwriting previous output if
                       any (default: ./findings).
  -s string            Strip this leading string from the reported key location paths (e.g., if you're
                       searching /tmp/inventory, you might set this to either /tmp or /tmp/inventory.) Note
                       that this operates on the path only, not the filename. '~' will be expanded.
```

Search the `sample-data` directory for keys:

```
$ ./__init__.py -p sample-data
2025-06-02 19:46:04,845 - INFO  - Found key of length 1801 at position 590 in sample-data/ps_snippet.txt
2025-06-02 19:46:04,922 - INFO  - Found key of length 227 at position 0 in sample-data/plain/ecdsa_pem
2025-06-02 19:46:04,949 - INFO  - Found mangled key of length 82 at position 0 in sample-data/plain/redacted_key
2025-06-02 19:46:04,977 - INFO  - Found key of length 400 at position 0 in sample-data/plain/ed25519
2025-06-02 19:46:05,007 - INFO  - Found key of length 1801 at position 474 in sample-data/homedirs/jbloggs/.viminfo
2025-06-02 19:46:05,015 - INFO  - Found key of length 1801 at position 2326 in sample-data/homedirs/jbloggs/.viminfo
2025-06-02 19:46:05,032 - INFO  - Found key of length 1801 at position 1 in sample-data/homedirs/jbloggs/tf.key
2025-06-02 19:46:05,225 - INFO  - Correlating keys...
2025-06-02 19:46:05,225 - INFO  - Writing findings to ./findings
```

This generates several files under findings, of which `private.json` is the
most important. This contains a list of JSON objects, each corresponding to a
unique private key. The structure looks like this:

```json
    {
        "encrypted": false,
        "sha256": "2048 SHA256:REoRXyGCovWtM87Lb/xUl3MaJQlPqB7SFLmqOBVtQ+k  (RSA)",
        "md5": "2048 MD5:4e:56:11:ba:31:7f:5b:88:d7:59:dd:d1:02:18:28:76  (RSA)",
        "priv": "-----BEGIN OPENSSH PRIVATE KEY-----...-----END OPENSSH PRIVATE KEY-----\n",
        "pub": "ssh-rsa ...",
        "privkey_locations": {
            "sample-data/ps_snippet.txt": [
                590
            ],
            "sample-data/plain/some_key": [
                0
            ]
        },
        "pubkey_locations": {
            "sample-data/configs/terraform.tfvars.json": [
                831
            ],
            "sample-data/plain/some_key.pub": [
                0
            ]
        }
    }
```

From this, we could guess that the key found in the output of a ps command (in
an environment variable) might get us into the host defined in
terraform.tfvars.json. The discovered keys are also extracted and stored
in individual files in findings/private, ready for use with `ssh -i`.

[jq](https://jqlang.github.io/jq/) is recommended for parsing
private.json. For example, you might want to list only the discovered
private keys for which public keys were also discovered:
```
jq -r '.[] | select(.pubkey_locations | length > 0) | {sha256: .sha256, pubkey_locations: .pubkey_locations, privkey_locations: .privkey_locations}' < findings/private.json
```

This will produce more compact output that looks something like this:

```json
{
  "sha256": "2048 SHA256:REoRXyGCovWtM87Lb/xUl3MaJQlPqB7SFLmqOBVtQ+k  (RSA)",
  "pubkey_locations": {
    "sample-data/plain/some_key.pub": [
      0
    ],
    "sample-data/configs/terraform.tfvars.json": [
      831
    ]
  },
```
