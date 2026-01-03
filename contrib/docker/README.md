# Mynta Core Docker Build System

This directory contains a Docker-based cross-compilation environment for building Mynta Core static executables for multiple platforms.

## Supported Platforms

| Platform | Target | Architecture |
|----------|--------|--------------|
| Linux | x86_64-pc-linux-gnu | 64-bit Intel/AMD |
| Windows | x86_64-w64-mingw32 | 64-bit Intel/AMD |
| macOS Intel | x86_64-apple-darwin | 64-bit Intel |
| macOS Silicon | aarch64-apple-darwin | 64-bit ARM (M1/M2/M3) |

## Quick Start

### 1. Build the Docker Image

From the repository root:

```bash
cd contrib/docker
docker build -t mynta-builder -f Dockerfile ../..
```

Or using docker-compose:

```bash
cd contrib/docker
docker-compose build
```

### 2. Build Binaries

**Linux:**
```bash
docker run -v $(pwd)/output:/output mynta-builder linux
```

**Windows:**
```bash
docker run -v $(pwd)/output:/output mynta-builder windows
```

**All platforms:**
```bash
docker run -v $(pwd)/output:/output mynta-builder all
```

### 3. Retrieve Binaries

Built binaries will be in the `output/` directory:

```
output/
├── linux-x86_64/
│   ├── myntad
│   └── mynta-cli
├── windows-x86_64/
│   ├── myntad.exe
│   └── mynta-cli.exe
├── mynta-linux-x86_64.tar.gz
└── mynta-windows-x86_64.zip
```

## Using Docker Compose

Docker Compose provides convenient shortcuts:

```bash
# Build the image
docker-compose build

# Build for Linux
docker-compose run --rm linux

# Build for Windows
docker-compose run --rm windows

# Build for all platforms
docker-compose run --rm all

# Show help
docker-compose run --rm builder help
```

## macOS Cross-Compilation

Building for macOS requires a macOS SDK due to Apple's licensing restrictions.

### Obtaining the SDK

1. On a Mac with Xcode installed, find the SDK:
   ```bash
   xcrun --show-sdk-path
   # Usually: /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk
   ```

2. Create a tarball of the SDK:
   ```bash
   cd /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/
   tar -cJf MacOSX11.3.sdk.tar.xz MacOSX11.3.sdk
   ```

3. Copy the tarball to your build machine.

### Building with the SDK

Mount the SDK when running the container:

```bash
docker run \
  -v $(pwd)/output:/output \
  -v $(pwd)/MacOSX11.3.sdk.tar.xz:/opt/osxcross/tarballs/MacOSX11.3.sdk.tar.xz:ro \
  mynta-builder macos-x86_64
```

## Build Options

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NPROC` | (auto) | Number of parallel build jobs |

### Build Targets

| Target | Description |
|--------|-------------|
| `linux` | Build for Linux x86_64 |
| `windows` | Build for Windows x86_64 |
| `macos-x86_64` | Build for macOS Intel |
| `macos-arm64` | Build for macOS Apple Silicon |
| `all` | Build for all platforms |
| `help` | Show usage information |

## Output Files

### Linux
- `myntad` - Daemon with JSON-RPC server
- `mynta-cli` - Command-line RPC client
- `mynta-tx` - Transaction utility (if available)

### Windows
- `myntad.exe` - Daemon with JSON-RPC server
- `mynta-cli.exe` - Command-line RPC client
- `mynta-tx.exe` - Transaction utility (if available)

### Archives
- `mynta-linux-x86_64.tar.gz` - Linux binaries archive
- `mynta-windows-x86_64.zip` - Windows binaries archive
- `mynta-macos-x86_64.tar.gz` - macOS Intel binaries archive
- `mynta-macos-arm64.tar.gz` - macOS ARM binaries archive

## Troubleshooting

### Build fails with "permission denied"

Ensure the build scripts have execute permissions:
```bash
chmod +x contrib/docker/scripts/*.sh
```

### Windows build fails with pthread errors

This is handled automatically by the build system, but if issues persist:
```bash
# Ensure mingw uses posix threads
update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix
```

### Out of memory during build

Reduce parallel jobs:
```bash
docker run -e NPROC=2 -v $(pwd)/output:/output mynta-builder linux
```

### macOS build fails with "SDK not found"

Ensure you've properly mounted the macOS SDK tarball. See the macOS section above.

## Advanced Usage

### Interactive Shell

To debug build issues, start an interactive shell:
```bash
docker run -it --entrypoint /bin/bash mynta-builder
```

### Custom Build Configuration

Mount a custom configuration:
```bash
docker run \
  -v $(pwd)/output:/output \
  -v $(pwd)/my-config.site:/mynta/depends/config.site:ro \
  mynta-builder linux
```

### Building Specific Version

Build from a specific git tag:
```bash
docker build \
  --build-arg GIT_TAG=v1.0.0 \
  -t mynta-builder:v1.0.0 \
  -f Dockerfile ../..
```

## Security Notes

1. **Verify downloads**: All dependency downloads in the `depends` system include SHA256 checksums.

2. **Reproducible builds**: Using Docker ensures a consistent build environment across machines.

3. **Static linking**: Linux builds use `-static-libgcc -static-libstdc++` for maximum portability.

4. **No GUI**: These builds are headless (daemon + CLI only) for security-focused deployments.

## License

Mynta Core is released under the MIT license. See [COPYING](../../COPYING) for more information.

