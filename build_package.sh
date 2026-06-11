#!/usr/bin/env bash
# ============================================================================
# build_package.sh — Build RFD + APPLaunch from source, then create .deb
#
# Usage:
#   ./build_package.sh              # build all and package
#   ./build_package.sh --skip-build # use existing dist/ binaries
#   ./build_package.sh --rfid-only  # only build & package RFID
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RFID_DIR="${REPO_ROOT}/projects/RFID"
APPL_DIR="${REPO_ROOT}/projects/APPLaunch"
BUILD_JOBS="${BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)}"
SKIP_BUILD="${SKIP_BUILD:-0}"
RFID_ONLY="${RFID_ONLY:-0}"

# Toolchain setup for macOS cross-compile
export PATH="/opt/homebrew/bin:$PATH"
if [[ "$(uname -s)" == "Darwin" ]]; then
  export CONFIG_TOOLCHAIN_PATH="${CONFIG_TOOLCHAIN_PATH:-/opt/homebrew/bin}"
fi

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[BUILD]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Parse args ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --skip-build) SKIP_BUILD=1; shift ;;
    --rfid-only)  RFID_ONLY=1;  shift ;;
    *) shift ;;
  esac
done

# ── Step 1: Build RFID ───────────────────────────────────────────────────────
if [[ "${SKIP_BUILD}" == "1" ]]; then
  info "Skip build, using existing dist/ binaries"
elif [[ ! -f "${RFID_DIR}/dist/M5CardputerZero-RFID" ]] || [[ "$(find "${RFID_DIR}/main" -name '*.cpp' -o -name '*.hpp' | xargs stat -f '%m' 2>/dev/null | sort -rn | head -1)" -gt "$(stat -f '%m' "${RFID_DIR}/dist/M5CardputerZero-RFID" 2>/dev/null || echo 0)" ]]; then
  info "Building RFID..."
  cd "${RFID_DIR}"
  rm -rf build
  CardputerZero=y scons -j"${BUILD_JOBS}"
  if [[ ! -f dist/M5CardputerZero-RFID ]]; then
    err "RFID build failed"
    exit 1
  fi
  info "RFID binary: $(ls -lh dist/M5CardputerZero-RFID | awk '{print $5}')"
else
  info "RFID binary up-to-date"
fi

# ── Step 2: Build APPLaunch (skip if rfid-only) ──────────────────────────────
if [[ "${RFID_ONLY}" != "1" ]]; then
  if [[ "${SKIP_BUILD}" != "1" ]]; then
    info "Building APPLaunch..."
    cd "${APPL_DIR}"
    rm -rf build
    CardputerZero=y scons -j"${BUILD_JOBS}"
    if [[ ! -f dist/M5CardputerZero-APPLaunch ]]; then
      err "APPLaunch build failed"
      exit 1
    fi
    info "APPLaunch binary: $(ls -lh dist/M5CardputerZero-APPLaunch | awk '{print $5}')"
  fi

  # Copy APPLaunch binary into RFID dist/ for packaging
  info "Staging APPLaunch binary for RFID .deb..."
  mkdir -p "${RFID_DIR}/dist_stage"
  cp -f "${APPL_DIR}/dist/M5CardputerZero-APPLaunch" "${RFID_DIR}/dist_stage/"
fi

# ── Step 3: Build mfkey tools if needed ──────────────────────────────────────
MFKEY_DIST="${RFID_DIR}/dist_mfkey"
MFKEY_SRC="${RFID_DIR}/main/tools/mfkey"
if [[ ! -f "${MFKEY_DIST}/mfkey32v2" || ! -f "${MFKEY_DIST}/mfkey64" ]]; then
  info "Building mfkey tools..."
  mkdir -p "${MFKEY_DIST}"
  _CC=""
  for c in "/opt/homebrew/bin/aarch64-unknown-linux-gnu-gcc" aarch64-linux-gnu-gcc aarch64-unknown-linux-gnu-gcc; do
    if command -v "$c" >/dev/null 2>&1 || [[ -x "$c" ]]; then _CC="$c"; break; fi
  done
  if [[ -z "${_CC}" ]]; then
    warn "No aarch64 cross-compiler, skip mfkey"
  else
    MFKEY_SRCS="${MFKEY_SRC}/crapto1/crapto1.c ${MFKEY_SRC}/crapto1/crypto1.c ${MFKEY_SRC}/crapto1/bucketsort.c ${MFKEY_SRC}/util_posix.c"
    "${_CC}" -O2 -I"${MFKEY_SRC}" -o "${MFKEY_DIST}/mfkey32v2" "${MFKEY_SRC}/mfkey32v2.c" ${MFKEY_SRCS} -lm -static && info "  mfkey32v2 OK" || warn "  mfkey32v2 FAIL"
    "${_CC}" -O2 -I"${MFKEY_SRC}" -o "${MFKEY_DIST}/mfkey64"   "${MFKEY_SRC}/mfkey64.c"   ${MFKEY_SRCS} -lm -static && info "  mfkey64 OK"   || warn "  mfkey64 FAIL"
  fi
fi

# ── Step 4: Build .deb ──────────────────────────────────────────────────────
info "Packaging .deb..."
cd "${RFID_DIR}"
python3 tools/package_deb.py --build-if-missing --revision "m5stack$(date +%Y%m%d)" "$@"

DEB_FILE=$(ls -t build/rfid_*.deb 2>/dev/null | head -1)
if [[ -n "${DEB_FILE}" ]]; then
  cp -f "${DEB_FILE}" "${REPO_ROOT}/"
  info "Package: ${REPO_ROOT}/$(basename ${DEB_FILE})"
else
  err "deb packaging failed"
  exit 1
fi
