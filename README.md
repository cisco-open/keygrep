# Keygrep

## Red team oriented key finder and correlator

```
$ ./__init__.py -h

usage: __init__.py [-h] [--include_mangled] [-p path] [-i state_file] [-o output_directory] [-s string]

Searches the specified directories for SSH keys and writes a report and all discovered public and private
keys to the output directory.

optional arguments:
  -h, --help           show this help message and exit
  --include_mangled    Include unrecovered "mangled" keys in results. Without this option, keygrep will
                       ignore discovered private keys for which the following is true: 1. The key is not
                       encrypted; and 2. A fingerprint was unable to be calculated. The keys that are
                       included this way may have been redacted or mangled (deliberately or not) beyond
                       keygrep's current parsing capabilities. They might be recoverable by hand. Including
                       this option may result in invalid key files, so consider this when feeding into
                       tools like Driftwood.
  -p path              Add this path to the list of directories to search for keys. May be used multiple
                       times.
  -i state_file        Load the keychain object from this file and write to it on close.
  -o output_directory  Store extracted keys and report in this directory, overwriting previous output if
                       any (default: ./findings).
  -s string            Strip this leading string from the reported key location paths (e.g., if you're
                       searching /tmp/inventory, you might set this to either /tmp or /tmp/inventory.) Note
                       that this operates on the path only, not the filename. '~' will be expanded.

```

```
$ ./__init__.py -p sample-data
2022-06-27 15:04:50,217 - INFO  - Found key of length 1799 in sample-data/ps_snippet.txt at position 590
2022-06-27 15:04:50,230 - INFO  - Found key of length 1799 in sample-data/homedirs/jbloggs/tf.key at position 1
2022-06-27 15:04:50,242 - INFO  - Found key of length 1799 in sample-data/homedirs/jbloggs/.viminfo at position 474
2022-06-27 15:04:50,255 - INFO  - Found key of length 1811 in sample-data/homedirs/jbloggs/.viminfo at position 2326
2022-06-27 15:04:50,260 - WARNING  - Key found at position 2326 in sample-data/homedirs/jbloggs/.viminfo is mangled
2022-06-27 15:04:50,537 - INFO  - Correlating keys...
2022-06-27 15:04:50,538 - INFO  - Writing findings to ./findings
```

```
$ cat findings/private.json

[
    {
        "privkey_locations": {
            "sample-data/ps_snippet.txt": [
                590
            ],
            "sample-data/plain/some_key": [
                0
            ]
        },
        "pubkey_locations": {
            "sample-data/plain/some_key.pub": [
                0
            ],
            "sample-data/configs/terraform.tfvars.json": [
                831
            ]
        }
    }
]
```

From this, we could guess that the key found in the output of a ps command (in
an environment variable) might get us into the host defined in
terraform.tfvars.json. The discovered keys are stored in individual files in
findings/private, ready for use with `ssh -i`.
