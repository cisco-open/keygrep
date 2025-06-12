#!/usr/bin/env bash
#
# generate-test-keys.sh
#
# Generates a set of SSH keypairs covering all combinations of:
#   1. Key formats: PKCS8, RFC4716, PEM
#   2. Algorithms: ed25519, dsa, rsa, ecdsa
#   3. Encryption: encrypted (passphrase "password") and unencrypted
#
# All keys (both private and public) will be placed under ./test-keys/.

set -euo pipefail

FORMATS=("PKCS8" "RFC4716" "PEM")
TYPES=("ed25519" "dsa" "rsa" "ecdsa")
PASSPHRASES=("" "password")

if [ "${#}" -ne 1 ]; then
    echo "Usage: ${0} output-directory" >&2
    exit 1
fi

OUTDIR="${1}"

mkdir -p "$OUTDIR"

for FORMAT in "${FORMATS[@]}"; do
  for TYPE in "${TYPES[@]}"; do
    for PASSPHRASE in "${PASSPHRASES[@]}"; do
      if [ -z "${PASSPHRASE}" ]; then
        SUFFIX="unencrypted"
        PASSARG=(-N "")
      else
        SUFFIX="encrypted"
        PASSARG=("-N" "${PASSPHRASE}")
      fi

      BASENAME="${FORMAT}_${TYPE}_${SUFFIX}"
      KEYPATH="${OUTDIR}/${BASENAME}"

      # Pick a sensible bit‐length flag for algorithms that need it
      case "$TYPE" in
        rsa)
          BITS="2048"
          ;;
        dsa)
          BITS="1024"
          ;;
        ecdsa)
          BITS="256"
          ;;
        ed25519)
          # ed25519 ignores -b, so leave BITS empty
          BITS=""
          ;;
        *)
          echo "Unknown key type: ${TYPE}" >&2
          exit 1
          ;;
      esac

      # Assemble ssh-keygen arguments into an array to avoid eval/quoting pitfalls
      ARGS=(ssh-keygen -t "$TYPE" -m "$FORMAT" -f "$KEYPATH" -q)
      if [ -n "$BITS" ]; then
        ARGS+=( -b "${BITS}" )
      fi
      ARGS+=( "${PASSARG[@]}" )

      if ! [ -e "${KEYPATH}" ]; then
          echo "Generating ${KEYPATH} (format=${FORMAT}, type=${TYPE}, ${SUFFIX})"
          "${ARGS[@]}"
      fi
    done
  done
done

echo "All test keys generated."
