#!/usr/bin/env python3
"""Keygrep tests"""

import json
from pathlib import Path
from keygrep.keychain import KeyChain
from keygrep.keygrep_utility import get_privkey_data, dsa_key_support


def test_correlation(tmp_path):
    """Test that private keys are correctly associated with public keys."""
    kc = KeyChain(output_dir=tmp_path, path_prefix="", include_mangled=False)
    kc.load_private_keys(Path(__file__).parent / "test-keys/openssh/ed25519_1")
    kc.load_public_keys(Path(__file__).parent / "test-keys/openssh/ed25519_1.pub")
    kc.correlate_keys()
    kc.write_summary()

    with open(tmp_path / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)

    assert Path(list(priv_data[0]["pubkey_locations"])[0]).name == "ed25519_1.pub"

def test_viminfo_unmangling(tmp_path):
    """Test .viminfo unmangling rules."""
    kc = KeyChain(output_dir=tmp_path, path_prefix="", include_mangled=False)
    kc.load_private_keys(Path(__file__).parent / "test-keys/viminfo")
    kc.write_summary()

    with open(tmp_path / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)

    assert {t["sha256"] for t in priv_data} == {"SHA256:L3k/oJubblSY0lB9Ulsl7emDMnRPKm/8udf2ccwk560",
                                                "SHA256:l6itGumSMcRBBAFteCgmjQBIXqLK/jFGUH3viHX1RmE"}

    for private_key in priv_data:
        if private_key["sha256"] == "SHA256:L3k/oJubblSY0lB9Ulsl7emDMnRPKm/8udf2ccwk560":
            assert list(private_key["privkey_locations"].values()) == [[446, 888]]
        if private_key["sha256"] == "SHA256:l6itGumSMcRBBAFteCgmjQBIXqLK/jFGUH3viHX1RmE":
            assert list(private_key["privkey_locations"].values()) == [[1323, 2251]]

def test_fingerprints(tmp_path):
    """Test that fingerprints are correctly generated."""

    files = ["ecdsa_1", "ecdsa_2", "ecdsa_sk1", "ecdsa_sk2", "ed25519_1",
             "ed25519_2", "ed25519_sk1", "ed25519_sk2", "rsa_1", "rsa_2"]

    if dsa_key_support():
        files.extend(["dsa_1", "dsa_2"])

    kc = KeyChain(output_dir=tmp_path)

    for file in files:
        kc.load_private_keys(Path(__file__).parent / "test-keys/openssh" / file)

        with open(Path(__file__).parent / "test-keys/openssh" / f"{file}.fp", "r", encoding="utf-8") as fp_file:
            assert kc.private_keys[-1].get("sha256") == fp_file.read().strip()


def test_identical_keys(tmp_path):
    """Test that for both public and private keys, keys with the same
    fingerprint are considered the same key."""
    test_data_dir = Path(__file__).parent / "test-keys/identical-keys"
    kc = KeyChain(output_dir=tmp_path)
    kc.load_private_keys(test_data_dir)
    kc.write_summary()

    with open(tmp_path / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)
    assert len(priv_data) == 1
    assert len(priv_data[0]["privkey_locations"]) == 5
    print("Identical private keys are correctly collapsed")

def test_invalid_public_keys(tmp_path):
    """Test that distinct invalid public keys are tracked."""

    kc = KeyChain(output_dir=tmp_path, path_prefix="", include_mangled=True)
    kc.load_public_keys(Path(__file__).parent / "test-keys/bad-keys")
    kc.write_summary()

    with open(tmp_path / "public.json", "r", encoding="utf-8") as inf:
        pub_data = json.load(inf)
    assert len(pub_data) == 2
    print("Distinct invalid public keys are separately recorded")

def test_openssh_keys(tmp_path):
    """Test that the expected results are generated from OpenSSH test keys."""

    kc = KeyChain(output_dir=tmp_path, path_prefix="", include_mangled=False)
    kc.load_private_keys(Path(__file__).parent / "test-keys/openssh")
    kc.load_public_keys(Path(__file__).parent / "test-keys/openssh")
    kc.write_summary()

    with open(tmp_path / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)

    # There should be 26 total instances of 15 distinct private keys.
    # 2 are distinct DSA keys, so without DSA support, 13 keys
    # should be identified when include_mangled=False
    assert len(priv_data) in (13, 15)

    n = 0
    for key in priv_data:
        # Note that each of these is actually a list of positions in the file where
        # the key was found. For this test data, there's only one key per file
        n+=len(key["privkey_locations"])

    # There are 4 DSA key files (dsa_1, dsa_2, dsa_n, dsa_n_pw) so 22 total keys without DSA support
    if dsa_key_support():
        assert n == 26
    else:
        assert n == 22

    for key in priv_data:
        # For OpenSSH formatted encrypted private keys, we can obtain the fingerprint and public key without the passphrase
        if "ENCRYPTED" not in key["priv"]:
            assert key["pub"] is not None
            assert key["sha256"] is not None
        # For PEM/PKCS8 formatted encrypted private keys, we cannot obtain the fingerprint or public key without the passphrase
        else:
            assert key["pub"] is None
            assert key["sha256"] is None

    with open(tmp_path / "public.json", "r", encoding="utf-8") as inf:
        pub_data = json.load(inf)

    # There should be 22 copies of 12 distinct public keys, or 19 and 10 if no DSA support
    # dsa_1.pub, dsa_1-cert.pub, dsa_2.pub

    if dsa_key_support():
        assert len(pub_data) == 12
    else:
        assert len(pub_data) == 10

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

    if dsa_key_support():
        assert n == 22
    else:
        assert n == 19

    # If include_mangled is False, we should always have a public key string
    # and fingerprint for each public key
    for key in pub_data:
        assert key["pub"] is not None
        assert key["sha256"] is not None

def test_encrypted_and_clear(tmp_path):
    """Check that cleartext keys replace encrypted keys if we have copies of
    both."""

    kc = KeyChain(output_dir=tmp_path, path_prefix="", include_mangled=False)
    # Load encrypted first, in a format where we can obtain the fingerprint
    kc.load_private_keys(Path(__file__).parent / "test-keys/openssh/ed25519_1_pw")
    # Load a cleartext copy of the same key
    kc.load_private_keys(Path(__file__).parent / "test-keys/openssh/ed25519_1")
    kc.write_summary()

    with open(tmp_path / "private.json", "r", encoding="utf-8") as inf:
        priv_data = json.load(inf)

    assert priv_data[0]["encrypted"] is False
    assert get_privkey_data(priv_data[0]["priv"])["encrypted"] is False
    print("Cleartext key replaces encrypted key")
