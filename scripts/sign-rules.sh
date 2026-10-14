#!/usr/bin/env bash
# Oreon Defense rule feed signing tool.
#
#   sign-rules.sh keygen  KEYDIR
#       Makes an Ed25519 key pair: KEYDIR/od-rules-ed25519.key (private)
#       and KEYDIR/od-rules-ed25519.pub (public). Keep the private key
#       off the source tree.
#
#   sign-rules.sh sign    PRIVATE_KEY RULES_YAML [OUTDIR]
#       Writes OUTDIR/rules.yaml, OUTDIR/rules.yaml.sig and
#       OUTDIR/manifest.json. OUTDIR defaults to the folder of RULES_YAML.
#       Upload those three files to the root of the od-rules bucket.
#
#   sign-rules.sh verify  PUBLIC_KEY DIR
#       Checks DIR/rules.yaml against DIR/rules.yaml.sig and DIR/manifest.json.
#
#   sign-rules.sh publish PRIVATE_KEY RULES_YAML BUCKET
#       sign, then upload with rclone (remote:bucket) or the aws cli
#       (R2 endpoint in R2_ENDPOINT). Set DRY_RUN=1 to only print.
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "$1 is required"; }
need openssl

cmd="${1:-}"
shift || true

rules_version() {
  # top level "version:" of the yaml document
  awk '/^version:[[:space:]]*[0-9]+/{print $2; exit}' "$1"
}

case "$cmd" in
  keygen)
    dir="${1:?KEYDIR required}"
    mkdir -p "$dir"
    chmod 700 "$dir"
    [[ -e "$dir/od-rules-ed25519.key" ]] && die "$dir/od-rules-ed25519.key already exists"
    umask 077
    openssl genpkey -algorithm ed25519 -out "$dir/od-rules-ed25519.key"
    openssl pkey -in "$dir/od-rules-ed25519.key" -pubout -out "$dir/od-rules-ed25519.pub"
    chmod 600 "$dir/od-rules-ed25519.key"
    chmod 644 "$dir/od-rules-ed25519.pub"
    echo "private key: $dir/od-rules-ed25519.key"
    echo "public key:  $dir/od-rules-ed25519.pub"
    echo "Copy the public key to data/keys/od-rules-ed25519.pub in the source tree."
    ;;

  sign)
    key="${1:?PRIVATE_KEY required}"
    src="${2:?RULES_YAML required}"
    out="${3:-$(dirname "$src")}"
    [[ -f "$key" ]] || die "no key at $key"
    [[ -f "$src" ]] || die "no rules at $src"
    ver="$(rules_version "$src")"
    [[ -n "$ver" ]] || die "rules file has no top level 'version: N'"
    mkdir -p "$out"
    if [[ "$(realpath "$src")" != "$(realpath -m "$out/rules.yaml")" ]]; then
      cp -f "$src" "$out/rules.yaml"
    fi
    if command -v python3 >/dev/null; then
      python3 - "$out/rules.yaml" <<'PY' || die "rules.yaml does not parse"
import sys
try:
    import yaml
except ImportError:
    sys.exit(0)
doc = yaml.safe_load(open(sys.argv[1]))
assert isinstance(doc, dict) and isinstance(doc.get("rules"), list), "missing rules list"
PY
    fi
    openssl pkeyutl -sign -rawin -inkey "$key" -in "$out/rules.yaml" -out "$out/rules.yaml.sig"
    sha="$(openssl dgst -sha256 -r "$out/rules.yaml" | awk '{print $1}')"
    size="$(wc -c < "$out/rules.yaml" | tr -d ' ')"
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat > "$out/manifest.json" <<JSON
{
  "format": 1,
  "version": $ver,
  "sha256": "$sha",
  "size": $size,
  "signature": "rules.yaml.sig",
  "algorithm": "ed25519",
  "published": "$now"
}
JSON
    echo "signed version $ver"
    echo "upload these to the bucket root:"
    echo "  $out/manifest.json"
    echo "  $out/rules.yaml"
    echo "  $out/rules.yaml.sig"
    ;;

  verify)
    pub="${1:?PUBLIC_KEY required}"
    dir="${2:?DIR required}"
    openssl pkeyutl -verify -rawin -pubin -inkey "$pub" -in "$dir/rules.yaml" \
      -sigfile "$dir/rules.yaml.sig" >/dev/null || die "signature check failed"
    sha="$(openssl dgst -sha256 -r "$dir/rules.yaml" | awk '{print $1}')"
    grep -q "\"sha256\": \"$sha\"" "$dir/manifest.json" || die "manifest sha256 does not match"
    mver="$(sed -n 's/.*"version": *\([0-9]*\).*/\1/p' "$dir/manifest.json")"
    [[ "$mver" == "$(rules_version "$dir/rules.yaml")" ]] || die "manifest version does not match rules.yaml"
    echo "ok: version $mver, signature good"
    ;;

  publish)
    key="${1:?PRIVATE_KEY required}"
    src="${2:?RULES_YAML required}"
    bucket="${3:?BUCKET required, for example od-rules}"
    stage="$(mktemp -d)"
    trap 'rm -rf "$stage"' EXIT
    "$0" sign "$key" "$src" "$stage"
    run() { if [[ "${DRY_RUN:-0}" == 1 ]]; then echo "+ $*"; else "$@"; fi; }
    # manifest goes last so clients never see a manifest without its files
    if command -v rclone >/dev/null && [[ -n "${RCLONE_REMOTE:-}" ]]; then
      run rclone copyto "$stage/rules.yaml" "$RCLONE_REMOTE:$bucket/rules.yaml"
      run rclone copyto "$stage/rules.yaml.sig" "$RCLONE_REMOTE:$bucket/rules.yaml.sig"
      run rclone copyto "$stage/manifest.json" "$RCLONE_REMOTE:$bucket/manifest.json"
    elif command -v aws >/dev/null && [[ -n "${R2_ENDPOINT:-}" ]]; then
      for f in rules.yaml rules.yaml.sig manifest.json; do
        ctype=application/octet-stream
        [[ $f == *.json ]] && ctype=application/json
        [[ $f == *.yaml ]] && ctype=text/yaml
        run aws s3 cp "$stage/$f" "s3://$bucket/$f" --endpoint-url "$R2_ENDPOINT" \
          --content-type "$ctype" --cache-control "max-age=300"
      done
    else
      die "set RCLONE_REMOTE (rclone) or R2_ENDPOINT (aws cli) to upload"
    fi
    ;;

  *)
    sed -n '2,25p' "$0"
    exit 1
    ;;
esac
