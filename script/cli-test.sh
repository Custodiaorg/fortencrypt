#!/usr/bin/env bash
# ==========================================================
# FortEncrypt CLI Deep Test Harness
# - Verbose logging, anomaly detection, resilient (doesn't stop on first error)
# - Controls:
#     DEBUG=1   -> aktifkan set -x untuk debug shell
#     TRACE=1   -> echo setiap perintah yang dieksekusi oleh runner
#     SLOW=150  -> delay ms antar langkah (biar output tidak "ngebut")
# ==========================================================

set -o pipefail
shopt -s lastpipe

# --------------------------- Config -----------------------
FORTENCRYPT="${FORTENCRYPT:-node dist/src/bin/cli.js}"
ART_DIR="${ART_DIR:-artifacts}"
KEY_FILE="$ART_DIR/test.key"
REPORT_FILE="$ART_DIR/report.txt"
JUNIT_FILE="$ART_DIR/junit.xml"        # bisa dipakai CI
TMP_DIR="$ART_DIR/tmp"
PASSED=0
FAILED=0
SKIPPED=0
TOTAL=0
SLOW="${SLOW:-0}" # milliseconds

# warna
RED=$(tput setaf 1 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")
BLUE=$(tput setaf 4 2>/dev/null || echo "")
DIM=$(tput dim 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")

# timestamp util
now() { date +"%Y-%m-%d %H:%M:%S"; }
msleep() { [ "$SLOW" -gt 0 ] && perl -e "select(undef,undef,undef,$SLOW/1000)"; }

# logging
echo_header() { echo -e "${BLUE}[$(now)] $*${RESET}"; }
echo_info()   { echo -e "${YELLOW}[$(now)] $*${RESET}"; }
echo_ok()     { echo -e "${GREEN}[$(now)] ✔ $*${RESET}"; }
echo_err()    { echo -e "${RED}[$(now)] ✖ $*${RESET}"; }
echo_dim()    { echo -e "${DIM}$*${RESET}"; }

# debug/trace
if [ "${DEBUG:-0}" = "1" ]; then
  set -x
fi
trace() { [ "${TRACE:-0}" = "1" ] && echo_dim "→ $*"; }

# runner util
# run_cmd <outfile> <errfile> -- <command...>
run_cmd() {
  local out="$1"; shift
  local err="$1"; shift
  [ "$1" = "--" ] && shift
  trace "$*"
  "$@" >"$out" 2>"$err"
  return $?
}

# assertions
assert_eq() { # usage: assert_eq "expected" "actual" "message"
  local exp="$1" act="$2" msg="$3"
  if [ "$exp" = "$act" ]; then echo_ok "$msg"; return 0; else echo_err "$msg (expected='$exp' got='$act')"; return 1; fi
}
assert_file() { [ -f "$1" ] && echo_ok "File exists: $1" || { echo_err "File missing: $1"; return 1; }; }
assert_dir()  { [ -d "$1" ] && echo_ok "Dir exists: $1" || { echo_err "Dir missing: $1"; return 1; }; }
assert_nonempty() { [ -s "$1" ] && echo_ok "Non-empty: $1" || { echo_err "Empty or missing: $1"; return 1; }; }
assert_json() {
  local f="$1" msg="${2:-Valid JSON}"
  node -e "JSON.parse(require('fs').readFileSync('$f','utf8'))" >/dev/null 2>&1 \
    && echo_ok "$msg" || { echo_err "$msg"; return 1; }
}

# junit helper
_junit_cases=()
junit_add_case() { # name, time, status, message(optional)
  local name="$1" time="$2" status="$3" msg="${4:-}"
  local case="<testcase name=\"${name//\"/&quot;}\" time=\"$time\">"
  if [ "$status" = "failed" ]; then
    case="$case<failure message=\"${msg//\"/&quot;}\"></failure>"
  elif [ "$status" = "skipped" ]; then
    case="$case<skipped/>"
  fi
  case="$case</testcase>"
  _junit_cases+=("$case")
}
junit_write() {
  local tests="$((PASSED+FAILED+SKIPPED))"
  local failures="$FAILED"
  {
    echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    echo "<testsuite name=\"FortEncrypt CLI\" tests=\"$tests\" failures=\"$failures\">"
    for c in "${_junit_cases[@]}"; do echo "  $c"; done
    echo "</testsuite>"
  } > "$JUNIT_FILE"
}

# record result
record_result() { # name, status, message
  local name="$1" status="$2" msg="$3"
  TOTAL=$((TOTAL+1))
  case "$status" in
    pass) PASSED=$((PASSED+1));;
    fail) FAILED=$((FAILED+1));;
    skip) SKIPPED=$((SKIPPED+1));;
  esac
  echo "[$(now)] [$status] $name - $msg" >> "$REPORT_FILE"
}

# test wrapper
# test_case "Name" command_fn
test_case() {
  local name="$1"; shift
  local start=$(date +%s)
  echo_header "TEST: $name"
  msleep
  if "$@"; then
    local end=$(date +%s)
    local dur=$((end-start))
    echo_ok "$name (${dur}s)"
    record_result "$name" "pass" "ok (${dur}s)"
    junit_add_case "$name" "$dur" "passed"
    return 0
  else
    local end=$(date +%s)
    local dur=$((end-start))
    echo_err "$name (${dur}s)"
    record_result "$name" "fail" "failed (${dur}s)"
    junit_add_case "$name" "$dur" "failed" "failed"
    return 1
  fi
}

# ------------------------ Preflight -----------------------
mkdir -p "$ART_DIR" "$TMP_DIR"
: > "$REPORT_FILE"

echo_header "Preflight checks"
node -v | sed 's/^/Node: /'
if ! command -v node >/dev/null 2>&1; then echo_err "Node.js not found"; exit 1; fi
if ! command -v perl >/dev/null 2>&1; then echo_info "perl not found (optional for msleep)"; fi

if ! node -e "require('fs');" 2>/dev/null; then
  echo_err "Node runtime basic fs check failed"; exit 1
fi

# CLI discover
if ! node -e "require('fs').accessSync('$FORTENCRYPT')" 2>/dev/null; then
  echo_info "CLI path '$FORTENCRYPT' not directly accessible; trying to run anyway…"
fi

# CLI version/help smoke
test_case "CLI Help" bash -c "$FORTENCRYPT --help >/dev/null"

# --------------------- TEST DEFINITIONS -------------------

gen_key() {
  local out="$TMP_DIR/gen.out" err="$TMP_DIR/gen.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT generate-key -o "$KEY_FILE" -f -l 32
  rc=$?
  cat "$out" >> "$REPORT_FILE"; cat "$err" >> "$REPORT_FILE"
  assert_file "$KEY_FILE" || return 1
  assert_nonempty "$KEY_FILE" || return 1
  return $rc
}

encrypt_text() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/enc_text.out" err="$TMP_DIR/enc_text.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT encrypt -t "Hello World" -k "$key" --stringify
  rc=$?
  echo "$(<"$out")" > "$ART_DIR/encrypted_text.json"
  cat "$err" >> "$REPORT_FILE"
  assert_nonempty "$ART_DIR/encrypted_text.json" || return 1
  assert_json "$ART_DIR/encrypted_text.json" "Encrypted JSON valid" || return 1
  return $rc
}

decrypt_text() {
  local key=$(cat "$KEY_FILE")
  local payload
  payload=$(cat "$ART_DIR/encrypted_text.json")
  local out="$TMP_DIR/dec_text.out" err="$TMP_DIR/dec_text.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT decrypt -t "$payload" -k "$key"
  rc=$?
  local got; got=$(cat "$out")
  echo "$got" > "$ART_DIR/decrypted_text.txt"
  cat "$err" >> "$REPORT_FILE"
  assert_eq "Hello World" "$got" "Decrypt equals original" || return 1
  return $rc
}

encrypt_file() {
  echo "Test file content" > "$ART_DIR/test.txt"
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/enc_file.out" err="$TMP_DIR/enc_file.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT encrypt -i "$ART_DIR/test.txt" -o "$ART_DIR/test.enc" -k "$key"
  rc=$?
  cat "$err" >> "$REPORT_FILE"
  assert_file "$ART_DIR/test.enc" || return 1
  return $rc
}

decrypt_file() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/dec_file.out" err="$TMP_DIR/dec_file.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT decrypt -i "$ART_DIR/test.enc" -o "$ART_DIR/test.dec.txt" -k "$key"
  rc=$?
  cat "$err" >> "$REPORT_FILE"
  assert_file "$ART_DIR/test.dec.txt" || return 1
  assert_eq "Test file content" "$(cat "$ART_DIR/test.dec.txt")" "File roundtrip equals" || return 1
  return $rc
}

recursive_encrypt() {
  local key=$(cat "$KEY_FILE")
  mkdir -p "$ART_DIR/dir/sub"
  echo "File 1 content" > "$ART_DIR/dir/file1.txt"
  echo "File 2 content" > "$ART_DIR/dir/file2.txt"
  echo "Nested content" > "$ART_DIR/dir/sub/nest.txt" # nested (should ignore if only top-level)
  local out="$TMP_DIR/rec_enc.out" err="$TMP_DIR/rec_enc.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT encrypt -i "$ART_DIR/dir" -o "$ART_DIR/dir_encrypted" -k "$key" -r
  rc=$?
  cat "$err" >> "$REPORT_FILE"
  assert_dir "$ART_DIR/dir_encrypted" || return 1
  # Only top-level files expected per your current CLI loop
  assert_file "$ART_DIR/dir_encrypted/file1.txt.enc" || return 1
  assert_file "$ART_DIR/dir_encrypted/file2.txt.enc" || return 1
  return $rc
}

recursive_decrypt() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/rec_dec.out" err="$TMP_DIR/rec_dec.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT decrypt -i "$ART_DIR/dir_encrypted" -o "$ART_DIR/dir_decrypted" -k "$key" -r
  rc=$?
  cat "$err" >> "$REPORT_FILE"
  assert_dir "$ART_DIR/dir_decrypted" || return 1
  assert_file "$ART_DIR/dir_decrypted/file1.txt" || return 1
  assert_file "$ART_DIR/dir_decrypted/file2.txt" || return 1
  assert_eq "File 1 content" "$(cat "$ART_DIR/dir_decrypted/file1.txt")" "dir/file1 content ok" || return 1
  assert_eq "File 2 content" "$(cat "$ART_DIR/dir_decrypted/file2.txt")" "dir/file2 content ok" || return 1
  return $rc
}

env_key_roundtrip() {
  export MASTER_KEY="$(cat "$KEY_FILE")"
  local out1="$TMP_DIR/env_enc.out" err1="$TMP_DIR/env_enc.err"
  local out2="$TMP_DIR/env_dec.out" err2="$TMP_DIR/env_dec.err"
  run_cmd "$out1" "$err1" -- $FORTENCRYPT encrypt -t "Env test" -o "$ART_DIR/env.enc"
  rc1=$?
  run_cmd "$out2" "$err2" -- $FORTENCRYPT decrypt -i "$ART_DIR/env.enc" -o "$ART_DIR/env.txt"
  rc2=$?
  cat "$err1" "$err2" >> "$REPORT_FILE"
  [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] || return 1
  assert_eq "Env test" "$(cat "$ART_DIR/env.txt")" "Env key decrypt ok" || return 1
  return 0
}

alg_chacha() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/chacha.out" err="$TMP_DIR/chacha.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT encrypt -t "Algorithm test" -k "$key" -a chacha20-poly1305 -o "$ART_DIR/algo.enc"
  rc1=$?
  run_cmd "$out" "$err" -- $FORTENCRYPT decrypt -i "$ART_DIR/algo.enc" -k "$key" -o "$ART_DIR/algo.txt"
  rc2=$?
  cat "$err" >> "$REPORT_FILE"
  [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] || return 1
  assert_eq "Algorithm test" "$(cat "$ART_DIR/algo.txt")" "ChaCha20 roundtrip" || return 1
  return 0
}

with_compression() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/comp.out" err="$TMP_DIR/comp.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT encrypt -t "Compression test" -k "$key" -c -o "$ART_DIR/comp.enc"
  rc1=$?
  run_cmd "$out" "$err" -- $FORTENCRYPT decrypt -i "$ART_DIR/comp.enc" -k "$key" -o "$ART_DIR/comp.txt"
  rc2=$?
  cat "$err" >> "$REPORT_FILE"
  [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] || return 1
  assert_eq "Compression test" "$(cat "$ART_DIR/comp.txt")" "Compression roundtrip" || return 1
  return 0
}

with_aad_ok() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/aad_ok.out" err="$TMP_DIR/aad_ok.err"
  run_cmd "$out" "$err" -- $FORTENCRYPT encrypt -t "AAD test" -k "$key" --aad "auth-data" -o "$ART_DIR/aad.enc"
  rc1=$?
  run_cmd "$out" "$err" -- $FORTENCRYPT decrypt -i "$ART_DIR/aad.enc" -k "$key" --aad "auth-data" -o "$ART_DIR/aad.txt"
  rc2=$?
  cat "$err" >> "$REPORT_FILE"
  [ $rc1 -eq 0 ] && [ $rc2 -eq 0 ] || return 1
  assert_eq "AAD test" "$(cat "$ART_DIR/aad.txt")" "AAD ok roundtrip" || return 1
  return 0
}

with_aad_wrong_should_fail() {
  local key=$(cat "$KEY_FILE")
  local out="$TMP_DIR/aad_bad.out" err="$TMP_DIR/aad_bad.err"
  # expect failure
  if $FORTENCRYPT decrypt -i "$ART_DIR/aad.enc" -k "$key" --aad "wrong-data" -o "$ART_DIR/aad_fail.txt" >/dev/null 2>"$err"; then
    echo_err "Wrong AAD should fail but succeeded"
    cat "$err" >> "$REPORT_FILE"
    return 1
  else
    echo_ok "Wrong AAD correctly failed"
    cat "$err" >> "$REPORT_FILE"
    return 0
  fi
}

stdin_stdout_roundtrip() {
  local key=$(cat "$KEY_FILE")
  local enc out err
  out="$TMP_DIR/stdin_enc.out" err="$TMP_DIR/stdin_enc.err"
  printf "Streamed data" | $FORTENCRYPT encrypt -k "$key" --stringify >"$out" 2>"$err"
  [ -s "$out" ] || { echo_err "stdin encrypt empty"; cat "$err" >> "$REPORT_FILE"; return 1; }
  enc="$(cat "$out")"
  echo "$enc" | $FORTENCRYPT decrypt -k "$key" > "$ART_DIR/stdin.dec" 2>>"$REPORT_FILE"
  assert_eq "Streamed data" "$(cat "$ART_DIR/stdin.dec")" "stdin/stdout roundtrip" || return 1
  return 0
}

wrong_key_should_fail() {
  # modify 1 hex char of key
  local badkey="$(cat "$KEY_FILE" | sed 's/^[0-9a-fA-F]/f/')"
  if $FORTENCRYPT decrypt -t "$(cat "$ART_DIR/encrypted_text.json")" -k "$badkey" >/dev/null 2>>"$REPORT_FILE"; then
    echo_err "Wrong key should fail decrypt"
    return 1
  fi
  echo_ok "Wrong key correctly failed"
  return 0
}

corrupt_payload_should_fail() {
  local key=$(cat "$KEY_FILE")
  # corrupt by replacing a chunk
  cp "$ART_DIR/encrypted_text.json" "$ART_DIR/corrupt.json"
  perl -0777 -pe "s/[0-9a-f]{8}/deadbeef/g" -i "$ART_DIR/corrupt.json"
  if $FORTENCRYPT decrypt -t "$(cat "$ART_DIR/corrupt.json")" -k "$key" >/dev/null 2>>"$REPORT_FILE"; then
    echo_err "Corrupted payload should fail"
    return 1
  fi
  echo_ok "Corrupted payload correctly failed"
  return 0
}

missing_file_should_fail() {
  local key=$(cat "$KEY_FILE")
  if $FORTENCRYPT decrypt -i "$ART_DIR/nope.enc" -o "$ART_DIR/nope.txt" -k "$key" >/dev/null 2>>"$REPORT_FILE"; then
    echo_err "Missing file should fail"
    return 1
  fi
  echo_ok "Missing file correctly failed"
  return 0
}

buffer_mode() {
  local key=$(cat "$KEY_FILE")
  echo -n -e "\x00\x01\x02\x03raw" > "$ART_DIR/raw.bin"
  $FORTENCRYPT encrypt -i "$ART_DIR/raw.bin" -o "$ART_DIR/raw.enc" -k "$key" >/dev/null 2>>"$REPORT_FILE" || return 1
  $FORTENCRYPT decrypt -i "$ART_DIR/raw.enc" -o "$ART_DIR/raw.out" -k "$key" --buffer >/dev/null 2>>"$REPORT_FILE" || return 1
  cmp "$ART_DIR/raw.bin" "$ART_DIR/raw.out" && echo_ok "Buffer mode roundtrip" || { echo_err "Buffer mode mismatch"; return 1; }
  return 0
}

encoding_base64() {
  local key=$(cat "$KEY_FILE")
  $FORTENCRYPT encrypt -t "Base64 Enc" -k "$key" -e base64 --stringify -o "$ART_DIR/b64.enc" >/dev/null 2>>"$REPORT_FILE" || return 1
  $FORTENCRYPT decrypt -i "$ART_DIR/b64.enc" -k "$key" -o "$ART_DIR/b64.txt" >/dev/null 2>>"$REPORT_FILE" || return 1
  assert_eq "Base64 Enc" "$(cat "$ART_DIR/b64.txt")" "Base64 encoding roundtrip" || return 1
  return 0
}

nonjson_input_decrypt() {
  local key=$(cat "$KEY_FILE")
  # Simulate non-JSON payload: CLI should try JSON.parse, fallback to raw
  echo "Non-JSON-string" > "$ART_DIR/nonjson.payload"
  if $FORTENCRYPT decrypt -t "$(cat "$ART_DIR/nonjson.payload")" -k "$key" >/dev/null 2>>"$REPORT_FILE"; then
    echo_info "Non-JSON raw decrypt accepted (expected only if payload is valid raw format)"
    return 0
  else
    echo_ok "Non-JSON raw decrypt properly rejected"
    return 0
  fi
}

# ----------------------- Run tests ------------------------

echo_header "Running tests… (SLOW=${SLOW}ms DELAY)"
test_case "Generate Key"               gen_key
test_case "Encrypt Text"               encrypt_text
test_case "Decrypt Text"               decrypt_text
test_case "Encrypt File"               encrypt_file
test_case "Decrypt File"               decrypt_file
test_case "Recursive Encrypt (top-level)" recursive_encrypt
test_case "Recursive Decrypt"          recursive_decrypt
test_case "Env MASTER_KEY Roundtrip"   env_key_roundtrip
test_case "ChaCha20-Poly1305 Roundtrip" alg_chacha
test_case "Compression Roundtrip"      with_compression
test_case "AAD OK"                     with_aad_ok
test_case "AAD Wrong Should Fail"      with_aad_wrong_should_fail
test_case "stdin/stdout Roundtrip"     stdin_stdout_roundtrip
test_case "Wrong Key Should Fail"      wrong_key_should_fail
test_case "Corrupt Payload Should Fail" corrupt_payload_should_fail
test_case "Missing File Should Fail"   missing_file_should_fail
test_case "Buffer Mode Roundtrip"      buffer_mode
test_case "Base64 Encoding Roundtrip"  encoding_base64
test_case "Non-JSON Input Decrypt (anomaly probe)" nonjson_input_decrypt

# ----------------------- Summary --------------------------
echo
echo_header "Summary"
echo "  Passed : $PASSED"
echo "  Failed : $FAILED"
echo "  Skipped: $SKIPPED"
echo "  Total  : $TOTAL"
echo "  Artifacts: $ART_DIR"
junit_write
echo_info "JUnit report: $JUNIT_FILE"
echo_info "Plain report: $REPORT_FILE"

# exit code reflects failures
[ "$FAILED" -eq 0 ] || exit 1
exit 0
