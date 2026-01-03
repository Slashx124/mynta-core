#!/bin/bash
# =============================================================================
# Mynta Core Build Script - Main Entry Point
# =============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="/mynta"
OUTPUT_DIR="/output"
NPROC=$(nproc)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "============================================================="
    echo "  $1"
    echo "============================================================="
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

show_help() {
    echo ""
    echo "Mynta Core Cross-Compilation Build System"
    echo ""
    echo "Usage: docker run -v \$(pwd)/output:/output mynta-builder <target>"
    echo ""
    echo "Available targets:"
    echo "  linux         Build for Linux x86_64"
    echo "  windows       Build for Windows x86_64"
    echo "  macos-x86_64  Build for macOS Intel (requires SDK)"
    echo "  macos-arm64   Build for macOS Apple Silicon (requires SDK)"
    echo "  all           Build for all platforms"
    echo "  help          Show this help message"
    echo ""
    echo "Output:"
    echo "  Binaries are placed in /output/<platform>/"
    echo ""
    echo "Examples:"
    echo "  docker run -v ./output:/output mynta-builder linux"
    echo "  docker run -v ./output:/output mynta-builder windows"
    echo "  docker run -v ./output:/output -v ./sdk:/sdk mynta-builder macos-x86_64"
    echo ""
}

# Build for Linux x86_64
build_linux() {
    print_header "Building Mynta Core for Linux x86_64"
    
    cd "$SOURCE_DIR"
    
    # Clean previous build
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true
    
    # Build dependencies
    print_header "Building dependencies for Linux..."
    cd depends
    make HOST=x86_64-pc-linux-gnu NO_QT=1 -j$NPROC
    
    # Fix line endings in generated files (CRLF -> LF)
    find . -name "config.site" -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.sh" -exec dos2unix {} \; 2>/dev/null || true
    cd "$SOURCE_DIR"
    
    # Build BLST library
    print_header "Building BLST library..."
    cd src/bls/blst
    ./build.sh
    cd "$SOURCE_DIR"
    
    # Configure and build
    print_header "Configuring build..."
    ./autogen.sh
    
    CONFIG_SITE="$SOURCE_DIR/depends/x86_64-pc-linux-gnu/share/config.site" \
    ./configure \
        --prefix=/ \
        --disable-bench \
        --disable-tests \
        --disable-gui-tests \
        --without-gui \
        --enable-reduce-exports \
        LDFLAGS="-static-libgcc -static-libstdc++"
    
    print_header "Compiling Mynta Core..."
    make -j$NPROC
    
    # Copy output
    mkdir -p "$OUTPUT_DIR/linux-x86_64"
    cp src/myntad "$OUTPUT_DIR/linux-x86_64/"
    cp src/mynta-cli "$OUTPUT_DIR/linux-x86_64/"
    cp src/mynta-tx "$OUTPUT_DIR/linux-x86_64/" 2>/dev/null || true
    
    # Create archive
    cd "$OUTPUT_DIR/linux-x86_64"
    tar -czvf ../mynta-linux-x86_64.tar.gz *
    
    print_success "Linux build complete!"
    print_success "Output: /output/linux-x86_64/"
}

# Build for Windows x86_64
build_windows() {
    print_header "Building Mynta Core for Windows x86_64"
    
    cd "$SOURCE_DIR"
    
    # Clean previous build
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true
    
    # Build dependencies for Windows
    print_header "Building dependencies for Windows..."
    cd depends
    make HOST=x86_64-w64-mingw32 NO_QT=1 -j$NPROC
    
    # Fix line endings in generated files (CRLF -> LF)
    find . -name "config.site" -exec dos2unix {} \; 2>/dev/null || true
    find . -name "*.sh" -exec dos2unix {} \; 2>/dev/null || true
    cd "$SOURCE_DIR"
    
    # Build BLST library for Windows
    print_header "Building BLST library for Windows..."
    cd src/bls/blst
    # Clean previous build
    rm -f *.o *.a 2>/dev/null || true
    # Cross-compile BLST for Windows
    x86_64-w64-mingw32-gcc -O2 -fno-builtin -fPIC -Wall -c ./src/server.c
    x86_64-w64-mingw32-gcc -O2 -fno-builtin -fPIC -Wall -c ./build/win64/add_mod_256-x86_64.asm -o add_mod_256.o 2>/dev/null || \
    x86_64-w64-mingw32-gcc -O2 -fno-builtin -fPIC -Wall -c ./build/assembly.S -o assembly.o
    x86_64-w64-mingw32-ar rc libblst.a *.o
    x86_64-w64-mingw32-ranlib libblst.a
    cd "$SOURCE_DIR"
    
    # Configure and build
    print_header "Configuring build for Windows..."
    ./autogen.sh
    
    CONFIG_SITE="$SOURCE_DIR/depends/x86_64-w64-mingw32/share/config.site" \
    ./configure \
        --prefix=/ \
        --host=x86_64-w64-mingw32 \
        --disable-bench \
        --disable-tests \
        --disable-gui-tests \
        --without-gui \
        --enable-reduce-exports
    
    print_header "Compiling Mynta Core for Windows..."
    make -j$NPROC
    
    # Copy output
    mkdir -p "$OUTPUT_DIR/windows-x86_64"
    cp src/myntad.exe "$OUTPUT_DIR/windows-x86_64/"
    cp src/mynta-cli.exe "$OUTPUT_DIR/windows-x86_64/"
    cp src/mynta-tx.exe "$OUTPUT_DIR/windows-x86_64/" 2>/dev/null || true
    
    # Create archive
    cd "$OUTPUT_DIR/windows-x86_64"
    zip -r ../mynta-windows-x86_64.zip *
    
    print_success "Windows build complete!"
    print_success "Output: /output/windows-x86_64/"
}

# Build for macOS x86_64 (Intel)
build_macos_x86_64() {
    print_header "Building Mynta Core for macOS x86_64 (Intel)"
    
    # Check for macOS SDK
    if [ ! -d "/opt/osxcross/target/bin" ] || [ ! -f "/opt/osxcross/target/bin/x86_64-apple-darwin*-clang" ]; then
        print_warning "macOS SDK not found or osxcross not built."
        print_warning "To build for macOS, you need to:"
        print_warning "  1. Obtain a macOS SDK (MacOSX11.3.sdk.tar.xz or similar)"
        print_warning "  2. Mount it when running the container:"
        print_warning "     docker run -v ./MacOSX11.3.sdk.tar.xz:/opt/osxcross/tarballs/MacOSX11.3.sdk.tar.xz ..."
        print_warning "  3. The SDK will be automatically set up on first run"
        echo ""
        print_warning "Skipping macOS x86_64 build."
        return 1
    fi
    
    cd "$SOURCE_DIR"
    
    # Clean previous build
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true
    
    # Build dependencies for macOS
    print_header "Building dependencies for macOS x86_64..."
    cd depends
    make HOST=x86_64-apple-darwin NO_QT=1 -j$NPROC
    cd "$SOURCE_DIR"
    
    # Configure and build
    print_header "Configuring build for macOS x86_64..."
    ./autogen.sh
    
    CONFIG_SITE="$SOURCE_DIR/depends/x86_64-apple-darwin/share/config.site" \
    ./configure \
        --prefix=/ \
        --host=x86_64-apple-darwin \
        --disable-bench \
        --disable-tests \
        --disable-gui-tests \
        --without-gui \
        --enable-reduce-exports
    
    print_header "Compiling Mynta Core for macOS x86_64..."
    make -j$NPROC
    
    # Copy output
    mkdir -p "$OUTPUT_DIR/macos-x86_64"
    cp src/myntad "$OUTPUT_DIR/macos-x86_64/"
    cp src/mynta-cli "$OUTPUT_DIR/macos-x86_64/"
    cp src/mynta-tx "$OUTPUT_DIR/macos-x86_64/" 2>/dev/null || true
    
    # Create archive
    cd "$OUTPUT_DIR/macos-x86_64"
    tar -czvf ../mynta-macos-x86_64.tar.gz *
    
    print_success "macOS x86_64 build complete!"
    print_success "Output: /output/macos-x86_64/"
}

# Build for macOS ARM64 (Apple Silicon)
build_macos_arm64() {
    print_header "Building Mynta Core for macOS ARM64 (Apple Silicon)"
    
    # Check for macOS SDK
    if [ ! -d "/opt/osxcross/target/bin" ]; then
        print_warning "macOS SDK not found or osxcross not built."
        print_warning "See macos-x86_64 target for setup instructions."
        print_warning "Skipping macOS ARM64 build."
        return 1
    fi
    
    cd "$SOURCE_DIR"
    
    # Clean previous build
    make clean 2>/dev/null || true
    make distclean 2>/dev/null || true
    
    # Build dependencies for macOS ARM64
    print_header "Building dependencies for macOS ARM64..."
    cd depends
    make HOST=aarch64-apple-darwin NO_QT=1 -j$NPROC
    cd "$SOURCE_DIR"
    
    # Configure and build
    print_header "Configuring build for macOS ARM64..."
    ./autogen.sh
    
    CONFIG_SITE="$SOURCE_DIR/depends/aarch64-apple-darwin/share/config.site" \
    ./configure \
        --prefix=/ \
        --host=aarch64-apple-darwin \
        --disable-bench \
        --disable-tests \
        --disable-gui-tests \
        --without-gui \
        --enable-reduce-exports
    
    print_header "Compiling Mynta Core for macOS ARM64..."
    make -j$NPROC
    
    # Copy output
    mkdir -p "$OUTPUT_DIR/macos-arm64"
    cp src/myntad "$OUTPUT_DIR/macos-arm64/"
    cp src/mynta-cli "$OUTPUT_DIR/macos-arm64/"
    cp src/mynta-tx "$OUTPUT_DIR/macos-arm64/" 2>/dev/null || true
    
    # Create archive
    cd "$OUTPUT_DIR/macos-arm64"
    tar -czvf ../mynta-macos-arm64.tar.gz *
    
    print_success "macOS ARM64 build complete!"
    print_success "Output: /output/macos-arm64/"
}

# Build all targets
build_all() {
    print_header "Building Mynta Core for All Platforms"
    
    build_linux
    build_windows
    build_macos_x86_64 || true
    build_macos_arm64 || true
    
    print_header "Build Summary"
    echo ""
    ls -la "$OUTPUT_DIR"/*.{tar.gz,zip} 2>/dev/null || echo "No archives created"
    echo ""
    print_success "All builds complete!"
}

# Main entry point
case "$1" in
    linux)
        build_linux
        ;;
    windows)
        build_windows
        ;;
    macos-x86_64|macos-intel)
        build_macos_x86_64
        ;;
    macos-arm64|macos-silicon)
        build_macos_arm64
        ;;
    all)
        build_all
        ;;
    help|--help|-h|"")
        show_help
        ;;
    *)
        print_error "Unknown target: $1"
        show_help
        exit 1
        ;;
esac

