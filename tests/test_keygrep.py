#!/usr/bin/env python3
"""Keygrep tests"""

import json
from pathlib import Path
from keygrep.keychain import KeyChain
from keygrep.keygrep_utility import get_privkey_data

# Test keys are from published OpenSSH test data
# Use download-test-keys.sh to set up

def run_keygrep(in_keys_dir, write_results_dir, include_mangled):
    """Run keygrep and write results to the provided directory."""
    kc = KeyChain(output_dir=write_results_dir, path_prefix="", include_mangled=include_mangled)
    kc.load_private_keys(in_keys_dir)
    kc.load_public_keys(in_keys_dir)
    kc.write_summary()
    kc.write_private_keys()
    kc.write_public_keys()

def test_identical_keys(tmp_path):
    """Check that for both public and private keys, keys with the same
    fingerprint are considered the same key."""
    out_dir = tmp_path / "findings"
    test_data_dir = Path(__file__).parent / "test-keys/identical-keys"

    run_keygrep(test_data_dir, out_dir, include_mangled=False)

    with open(out_dir / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)
    assert len(priv_data) == 1
    assert len(priv_data[0]["privkey_locations"]) == 5
    print("Identical private keys are correctly collapsed")

def test_invalid_public_keys(tmp_path):
    """Check that distinct invalid public keys are tracked."""
    out_dir = tmp_path / "findings"
    test_data_dir = Path(__file__).parent / "test-keys/bad-keys"

    run_keygrep(test_data_dir, out_dir, include_mangled=True)

    with open(out_dir / "public.json", "r", encoding="utf-8") as inf:
        pub_data = json.load(inf)
    assert len(pub_data) == 2
    print("Distinct invalid public keys are separately recorded")

def test_openssh_keys(tmp_path):
    """Test that the expected results are generated from OpenSSH test keys."""

    out_dir = tmp_path / "findings"
    test_data_dir = Path(__file__).parent / "test-keys/openssh"

    run_keygrep(test_data_dir, out_dir, include_mangled=False)

    with open(out_dir / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)

    # There should be 26 copies of 15 distinct private keys
    assert len(priv_data) == 15

    n = 0
    for key in priv_data:
        # Note that each of these is actually a list of positions in the file where
        # the key was found. For this test data, there's only one key per file
        n+=len(key["privkey_locations"])

    assert n == 26

    for key in priv_data:
        # For OpenSSH formatted encrypted private keys, we can obtain the fingerprint and public key without the passphrase
        if "ENCRYPTED" not in key["priv"]:
            assert key["pub"] is not None
            assert key["sha256"] is not None
        # For PEM/PKCS8 formatted encrypted private keys, we cannot obtain the fingerprint or public key without the passphrase
        else:
            assert key["pub"] is None
            assert key["sha256"] is None

    with open(out_dir / "public.json", "r", encoding="utf-8") as inf:
        pub_data = json.load(inf)

    # There should be 22 copies of 12 distinct public keys
    assert len(pub_data) == 12

    # Note that the reason there are 15 "distinct" private keys and only 12
    # public keys is that rsa_1_pw, ecdsa_1_pw, and dsa_1_pw are encrypted PEM
    # files. This means the entire file, including the public key portion, is
    # encrypted. We therefore cannot determine their fingerprints and so
    # must treat them as distinct private keys.

    n = 0
    for key in pub_data:
        # Note that each of these is actually a list of positions in the file where
        # the key was found. For this test data, there's only one key per file
        n+=len(key["pubkey_locations"])

    assert n == 22

    # If include_mangled is False, we should always have a public key string
    # and fingerprint for each public key
    for key in pub_data:
        assert key["pub"] is not None
        assert key["sha256"] is not None

def test_encrypted_and_clear(tmp_path):
    """Check that cleartext keys replace encrypted keys if we have copies of
    both."""
    out_dir = tmp_path / "findings"

    kc = KeyChain(output_dir=out_dir, path_prefix="", include_mangled=False)
    # Load encrypted first, in a format where we can obtain the fingerprint
    kc.load_private_keys(Path(__file__).parent / "test-keys/openssh/ed25519_1_pw")
    # Load a cleartext copy of the same key
    kc.load_private_keys(Path(__file__).parent / "test-keys/openssh/ed25519_1")
    kc.write_summary()

    with open(out_dir / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)

    assert priv_data[0]["encrypted"] is False
    assert get_privkey_data(priv_data[0]["priv"])["encrypted"] is False
    print("Cleartext key replaces encrypted key")
