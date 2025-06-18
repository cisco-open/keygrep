#!/usr/bin/env bash

# Obtain and set up OpenSSH test keys
# This is just a quick script to download the test keys without having to store
# them in the repo.

set -euo pipefail

if [ "${#}" -ne 1 ]; then
    echo "Usage: ${0} output-directory" >&2
    exit 1
fi

OUTDIR="${1}"

if [ -d "${OUTDIR}" ]; then
    exit
fi

mkdir -p "${OUTDIR}"

if [ ! -d openssh-portable ]; then
    git clone https://github.com/openssh/openssh-portable.git
fi

cd openssh-portable

# Commit containing DSA keys
git checkout e95c0a0e964827722d29b4bc00d5c0ff4afe0ed2

cp -r regress/unittests/sshkey/testdata "../${OUTDIR}/openssh"
cd ..
rm -rf openssh-portable

mkdir "${OUTDIR}/identical-keys"

cp "${OUTDIR}/openssh/rsa_1" \
    "${OUTDIR}/openssh/rsa_1_sha1" \
    "${OUTDIR}/openssh/rsa_1_sha512" \
    "${OUTDIR}/openssh/rsa_n" \
    "${OUTDIR}/openssh/rsa_n_pw" \
    "${OUTDIR}/identical-keys"

mkdir "${OUTDIR}/bad-keys"
sed -e "s/AAAA/XXXX/" "${OUTDIR}/openssh/ed25519_2.pub" > "${OUTDIR}/bad-keys/ed25519_2A.pub"
sed -e "s/AAAA/YYYY/" "${OUTDIR}/openssh/ed25519_2.pub" > "${OUTDIR}/bad-keys/ed25519_2B.pub"
