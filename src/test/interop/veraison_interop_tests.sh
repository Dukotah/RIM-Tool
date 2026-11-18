#!/bin/bash
# RIM Tool <-> Veraison CoRIM round-trip conformance tests (fork only).
#
# Needs: build/libs/rim-tool*.jar, cocli (github.com/veraison/cocli) and
# corim-interop (src/test/interop/corim-interop) on PATH.
#
# Each case is one of:
#   interop_pass     - must work today
#   interop_mismatch - known interop failure; the case PASSES while the
#                      mismatch is still there and FAILS once it is fixed,
#                      so the expectation gets updated instead of rotting.

scriptDir=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
dataDir=$scriptDir/../../../data
rim="java -jar $(ls $scriptDir/../../../build/libs/rim-tool*.jar)"
cert=$dataDir/certs/COMP_OEM1_rim_signer_ecc_512_sha384.pem
key=$dataDir/keys/COMP_OEM1_rim_signer_ecc_512_sha384.key
v=$scriptDir/veraison
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failCount=0
log=$tmp/out.txt

for tool in cocli corim-interop; do
  command -v $tool >/dev/null || { echo "missing $tool on PATH"; exit 1; }
done

# fixture CMD...: building inputs must not fail
fixture() {
  if ! "$@" >"$log" 2>&1; then
    echo "fixture step failed: $*"
    cat "$log"
    exit 1
  fi
}

# run CMD..., succeed only if it exits 0 and prints no "skipping malformed"
# or "unmatched CBOR tag" line (cocli reports those but still exits 0)
run() {
  "$@" >"$log" 2>&1
  local rc=$?
  if [ $rc -eq 0 ] && grep -qE "skipping malformed|unmatched CBOR tag" "$log"; then
    rc=3
  fi
  return $rc
}

interop_pass() {
  local name=$1; shift
  if run "$@"; then
    echo "PASSED: $name"
  else
    echo "FAILED: $name"
    sed 's/^/    /' "$log" | head -5
    failCount=$((failCount + 1))
  fi
}

interop_mismatch() {
  local name=$1 expect=$2; shift 2
  if run "$@"; then
    echo "FAILED: $name now works; the known mismatch is gone, update this test"
    failCount=$((failCount + 1))
  elif grep -qF -- "$expect" "$log"; then
    echo "PASSED: $name (known mismatch: $expect)"
  else
    echo "FAILED: $name failed differently than expected (wanted: $expect)"
    sed 's/^/    /' "$log" | head -5
    failCount=$((failCount + 1))
  fi
}

echo "== Fixtures"
# RIM Tool CoRIMs. corim_1.json uses entity roles [0, 1]; the draft only
# defines CoRIM roles 1 and 2, so a [1] copy isolates the tag encoding issue.
sed 's/"role": \[ 0, 1 \]/"role": [ 1 ]/' $dataDir/corim/corim_1.json > $tmp/corim_role1.json
fixture $rim create -r corim_comid -c $dataDir/corim/corim_1.json -u --out $tmp/rt-unsigned.cbor
fixture $rim create -r corim_comid -c $tmp/corim_role1.json -u --out $tmp/rt-role1.cbor
fixture $rim create -r corim_comid -c $dataDir/corim/corim_1.json -p $cert -k $key --out $tmp/rt-signed.cose
# Veraison CoRIMs built by cocli from the cocli test data (Apache-2.0)
fixture cocli corim create -t $v/corim-tstr-id.json -m $v/comid-dice-refval.cbor -o $tmp/v-comid.cbor
fixture cocli corim create -t $v/corim-tstr-id.json -s $v/coswid-1.cbor -o $tmp/v-coswid.cbor
fixture cocli corim create -t $v/corim-uuid-id.json -m $v/comid-dice-refval.cbor -o $tmp/v-uuid.cbor
corim-interop jwk $key > $tmp/key.jwk || exit 1
echo "built $(ls $tmp | wc -l) files"

echo "== RIM Tool -> Veraison"
interop_mismatch "R1 cocli decodes RIM Tool unsigned CoRIM" \
  "cannot unmarshal byte string into Go value of type cbor.Tag" \
  cocli corim display -f $tmp/rt-unsigned.cbor
interop_mismatch "R2 cocli decodes RIM Tool signed CoRIM" \
  "error decoding CoRIM" \
  cocli corim display -f $tmp/rt-signed.cose
interop_pass "R3 go-cose verifies RIM Tool COSE_Sign1 signature" \
  corim-interop cose-verify -cert $cert $tmp/rt-signed.cose
fixture corim-interop rewrap -to spec $tmp/rt-role1.cbor $tmp/rt-role1-spec.cbor
interop_pass "R4 cocli decodes RIM Tool CoRIM once tags are re-wrapped to #6.506(bstr)" \
  cocli corim display -f $tmp/rt-role1-spec.cbor --show-tags
fixture corim-interop rewrap -to spec $tmp/rt-unsigned.cbor $tmp/rt-spec.cbor
interop_mismatch "R5 cocli accepts corim_1.json entity roles [0, 1]" "unknown role 0" \
  cocli corim display -f $tmp/rt-spec.cbor

echo "== Veraison -> RIM Tool"
for f in v-comid v-coswid v-uuid; do
  fixture cocli corim sign -f $tmp/$f.cbor -k $tmp/key.jwk -m $v/meta.json -o $tmp/$f.cose
done
interop_pass "V1 RIM Tool verifies cocli-signed CoRIM signature" \
  $rim verify -r corim_comid --in $tmp/v-comid.cose -p $cert
interop_mismatch "V2 RIM Tool prints cocli CoRIM (CoMID)" \
  'because "this.content" is null' \
  $rim print -r corim_comid --in $tmp/v-comid.cose
interop_mismatch "V3 RIM Tool prints cocli CoRIM with uuid corim-id" \
  "cannot be cast to class java.lang.String" \
  $rim print -r corim_comid --in $tmp/v-uuid.cose
for f in v-comid v-coswid; do
  fixture corim-interop rewrap -to legacy $tmp/$f.cbor $tmp/$f-legacy.cbor
  fixture $rim sign -r corim_comid --in $tmp/$f-legacy.cbor --out $tmp/$f-legacy.cose -p $cert -k $key
done
interop_pass "V4 RIM Tool prints cocli CoMID once tags are re-wrapped to bstr(#6.506)" \
  $rim print -r corim_comid --in $tmp/v-comid-legacy.cose
interop_mismatch "V5 RIM Tool parses CoSWID with text tag-id" "broken Base64 encoding" \
  $rim print -r corim_comid --in $tmp/v-coswid-legacy.cose

echo "== CoTL (tag 508)"
fixture corim-interop add-cotl $tmp/v-comid.cbor $tmp/v-cotl.cbor
interop_mismatch "T1 cocli displays a CoTL" "unmatched CBOR tag: 508" \
  cocli corim display -f $tmp/v-cotl.cbor --show-tags
fixture corim-interop rewrap -to legacy $tmp/v-cotl.cbor $tmp/v-cotl-legacy.cbor
fixture $rim sign -r corim_comid --in $tmp/v-cotl-legacy.cbor --out $tmp/v-cotl-legacy.cose -p $cert -k $key
interop_mismatch "T2 RIM Tool parses a CoTL" \
  "CoTL data (CBor Tag 508) found within the CoRIM data is not currently supported" \
  $rim print -r corim_comid --in $tmp/v-cotl-legacy.cose

if [ $failCount -eq 0 ]; then
  echo "All Veraison interop tests passed."
  exit 0
else
  echo "$failCount Veraison interop tests failed."
  exit 1
fi
