# =============================================================================
# Mynta Core Cross-Compilation Docker Image
# =============================================================================
# This image provides a complete build environment for compiling Mynta Core
# static executables for multiple target platforms:
#   - Linux x86_64
#   - Windows x86_64
#   - macOS x86_64 (Intel)
#   - macOS ARM64 (Apple Silicon)
#
# Usage:
#   docker build -t mynta-builder .
#   docker run -v $(pwd)/output:/output mynta-builder linux
#   docker run -v $(pwd)/output:/output mynta-builder windows
#   docker run -v $(pwd)/output:/output mynta-builder macos-x86_64
#   docker run -v $(pwd)/output:/output mynta-builder macos-arm64
#   docker run -v $(pwd)/output:/output mynta-builder all
# =============================================================================

FROM ubuntu:22.04

LABEL maintainer="Mynta Developers"
LABEL description="Cross-compilation environment for Mynta Core"
LABEL version="1.0"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# =============================================================================
# Install base build dependencies
# =============================================================================
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils \
    python3 \
    # Version control
    git \
    # Cross-compilation for Windows
    mingw-w64 \
    g++-mingw-w64-x86-64 \
    # Utilities
    curl \
    wget \
    dos2unix \
    zip \
    unzip \
    cmake \
    # Libraries for native builds
    libssl-dev \
    libevent-dev \
    libboost-all-dev \
    libdb-dev \
    libdb++-dev \
    libzmq3-dev \
    # For macOS cross-compilation (osxcross dependencies)
    clang \
    llvm \
    libxml2-dev \
    uuid-dev \
    libssl-dev \
    bash \
    patch \
    make \
    tar \
    xz-utils \
    bzip2 \
    gzip \
    sed \
    cpio \
    libbz2-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

# Set mingw32 to use POSIX threads (required for C++11 threading)
RUN update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix && \
    update-alternatives --set x86_64-w64-mingw32-gcc /usr/bin/x86_64-w64-mingw32-gcc-posix

# =============================================================================
# Install OSXCross for macOS cross-compilation
# =============================================================================
WORKDIR /opt

# Clone osxcross
RUN git clone https://github.com/tpoechtrager/osxcross.git

# Note: Users need to provide their own macOS SDK
# Download instructions will be provided in the README
# For now, we'll set up the structure and the SDK can be mounted at runtime

ENV OSXCROSS_ROOT=/opt/osxcross
ENV PATH="${OSXCROSS_ROOT}/target/bin:${PATH}"

# =============================================================================
# Copy Mynta Core source
# =============================================================================
WORKDIR /mynta
COPY . /mynta/

# Fix line endings for all shell scripts and makefiles
RUN find /mynta -name "*.sh" -exec dos2unix {} \; 2>/dev/null || true && \
    find /mynta -name "*.ac" -exec dos2unix {} \; 2>/dev/null || true && \
    find /mynta -name "*.am" -exec dos2unix {} \; 2>/dev/null || true && \
    find /mynta -name "*.mk" -exec dos2unix {} \; 2>/dev/null || true

# Initialize git submodules
RUN git config --global --add safe.directory /mynta && \
    git submodule update --init --recursive || true

# =============================================================================
# Copy build scripts
# =============================================================================
COPY contrib/docker/scripts/ /scripts/
RUN chmod +x /scripts/*.sh

# =============================================================================
# Create output directory
# =============================================================================
RUN mkdir -p /output

# =============================================================================
# Set default entrypoint
# =============================================================================
ENTRYPOINT ["/scripts/build.sh"]
CMD ["help"]

