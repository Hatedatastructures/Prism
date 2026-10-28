#!/usr/bin/env bash
# gen-reality-keys.sh — 生成 Reality (X25519) 密钥对 + short-id
# 用法: bash gen-reality-keys.sh
# 支持: Windows (Git Bash/MSYS2), Linux, macOS

set -euo pipefail

# 临时文件
if [[ "${OSTYPE:-}" == "msys" || "${OSTYPE:-}" == "win32" || "${OSTYPE:-}" == "cygwin" ]]; then
    KEYFILE="${TEMP:-/tmp}/x25519_$$.pem"
else
    KEYFILE=$(mktemp /tmp/x25519_XXXXXX.pem)
fi
trap 'rm -f "$KEYFILE"' EXIT

# 生成 X25519 密钥对
openssl genpkey -algorithm X25519 -out "$KEYFILE" 2>/dev/null

# 从 text 输出提取 hex → 拼接 → 转 binary → base64
extract_priv() {
    openssl pkey -in "$KEYFILE" -text -noout 2>/dev/null \
        | sed -n '/priv:/,/pub:/{/priv:/d;/pub:/d;p}' \
        | tr -d ' :\n\r' \
        | xxd -r -p \
        | base64 -w0
    echo
}

extract_pub() {
    openssl pkey -in "$KEYFILE" -pubout -text -noout 2>/dev/null \
        | sed -n '/pub:/,/ASN1/{/pub:/d;/ASN1/d;p}' \
        | tr -d ' :\n\r' \
        | xxd -r -p \
        | base64 -w0
    echo
}

PRIV_B64=$(extract_priv)
# 客户端需要 base64url 无 padding（Mihomo: base64.RawURLEncoding）
PUB_B64URL=$(extract_pub | tr '+/' '-_' | tr -d '=')
SHORT_ID=$(openssl rand -hex 8)

echo "=== Reality 密钥对 ==="
echo ""
echo "Private Key (服务端 private_key):"
echo "  $PRIV_B64"
echo ""
echo "Public Key (客户端 public-key, base64url):"
echo "  $PUB_B64URL"
echo ""
echo "Short ID (两边都要配):"
echo "  $SHORT_ID"
echo ""
echo "=== Prism 服务端 configuration.json ==="
cat << JSON
"reality": {
    "dest": "www.microsoft.com:443",
    "server_names": ["www.microsoft.com"],
    "private_key": "$PRIV_B64",
    "short_ids": ["$SHORT_ID"]
},
JSON
echo ""
echo "=== Clash 客户端 reality-opts ==="
cat << YAML
reality-opts:
  public-key: "$PUB_B64URL"
  short-id: "$SHORT_ID"
YAML
