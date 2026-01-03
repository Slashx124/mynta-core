#!/bin/bash
# Build script for cross-compiling Mynta Core for Windows
# Run this script in Ubuntu/WSL with mingw-w64 installed
#
# Prerequisites:
#   sudo apt-get install -y build-essential libtool autotools-dev automake \
#       pkg-config bsdmainutils python3 git dos2unix \
#       g++-mingw-w64-x86-64 mingw-w64-x86-64-dev
#   sudo update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
#   sudo update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clean Windows PATH if running in WSL (paths with spaces/parens break the build)
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

echo "=== Mynta Core Windows Build Script ==="
echo ""

# Check for mingw
if ! command -v x86_64-w64-mingw32-g++ &> /dev/null; then
    echo "ERROR: mingw-w64 is not installed. Install it with:"
    echo "  sudo apt-get install g++-mingw-w64-x86-64 mingw-w64-x86-64-dev"
    exit 1
fi

# Initialize submodules
echo "[1/6] Initializing submodules..."
git submodule update --init --recursive

# Fix line endings if needed
echo "[2/6] Fixing line endings..."
find . -name '*.sh' -exec dos2unix {} \; 2>/dev/null || true
dos2unix autogen.sh configure.ac Makefile.am 2>/dev/null || true

# Build BLST library for Windows
echo "[3/6] Building BLST library for Windows..."
cd src/bls/blst
rm -f libblst.a *.o 2>/dev/null || true
CC=x86_64-w64-mingw32-gcc ./build.sh
cd "$SCRIPT_DIR"

# Build dependencies
echo "[4/6] Building dependencies for Windows (this takes 15-30 minutes)..."
cd depends
make HOST=x86_64-w64-mingw32 NO_QT=1 -j$(nproc)
cd "$SCRIPT_DIR"

# Run autogen
echo "[5/6] Running autogen.sh..."
./autogen.sh

# Configure for Windows
echo "[6/6] Configuring and building for Windows..."
export CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site
./configure \
    --prefix=/ \
    --disable-bench \
    --disable-tests \
    --disable-shared \
    --without-gui \
    --with-incompatible-bdb \
    PTHREAD_LIBS='-lpthread' \
    LIBS='-lpthread'

make -j$(nproc)

echo ""
echo "=== Build Complete ==="
echo "Binaries are located at:"
echo "  src/myntad.exe"
echo "  src/mynta-cli.exe"
echo ""
echo "These are standalone executables that can be copied to any Windows 10/11 x64 system."

