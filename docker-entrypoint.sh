#!/bin/sh
set -eu

if [ -z "${VGRT_RSA_PUBLIC_KEY:-}" ] || [ -z "${VGRT_RSA_PRIVATE_KEY:-}" ]; then
    key_lines=$(java -jar /app/app.jar --generate-crypto-keys)
    VGRT_RSA_PUBLIC_KEY=$(printf '%s\n' "$key_lines" | sed -n 's/^VGRT_RSA_PUBLIC_KEY=//p')
    VGRT_RSA_PRIVATE_KEY=$(printf '%s\n' "$key_lines" | sed -n 's/^VGRT_RSA_PRIVATE_KEY=//p')
    export VGRT_RSA_PUBLIC_KEY VGRT_RSA_PRIVATE_KEY
fi

exec java -jar /app/app.jar