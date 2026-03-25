# Building PAP C++ Examples

## Prerequisites

- **CMake** 3.20+
- **C++ compiler**: GCC 13+, Clang 16+, or MSVC 2019+
- **Rust** (to build `libpap_c`)
- **cargo** and **rustup**

## Quick Build (Full Setup)

### 1. Build Rust C library

From the repository root:

```bash
cd pap
cargo build -p pap-c --release
```

This builds `libpap_c` to `target/release/`.

### 2. Build C++ Examples

From `bindings/cpp/`:

```bash
mkdir -p build
cd build
cmake -DPAP_ROOT=../.. ..
cmake --build .
ctest --output-on-failure
```

## Output

After successful build:

```
build/
├── example_basic_flow          # ~150 KB (includes libpap_c symbols)
├── example_raii_and_errors     # ~150 KB
└── example_delegation_chain    # ~150 KB
```

Run tests:

```bash
ctest --output-on-failure
./example_basic_flow
./example_raii_and_errors
./example_delegation_chain
```

## Troubleshooting

### CMake cannot find libpap_c

**Error:** `find_library could not find PAP_C_LIB`

**Fix:** Build `pap-c` first:

```bash
cd pap
cargo build -p pap-c --release
```

If `cargo` fails, check:

```bash
rustc --version      # Should be 1.70+
cargo --version      # Should be 1.70+
```

### Link errors on macOS

**Error:** `ld: symbol not found for architecture x86_64`

**Fix:** The CMakeLists.txt includes CoreFoundation/Security. If linking still fails:

```bash
# Check libpap_c symbols
nm target/release/libpap_c.a | grep pap_keypair_generate

# Try with explicit framework path
cmake -DCMAKE_FIND_DEBUG_MODE=ON ..
```

### Compiler version mismatch

**Error:** `error: C++ version below C++17 or unknown compiler`

**Fix:** Set explicit compiler:

```bash
cmake -DCMAKE_CXX_COMPILER=clang++-16 ..
```

Or update system defaults:

```bash
# Update-alternatives on Linux
sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++-16 100

# Check version
c++ --version
```

## Manual Compilation (No CMake)

If you prefer to compile manually:

```bash
# Build pap-c first
cd pap
cargo build -p pap-c --release

# Compile example
cd bindings/cpp/examples
g++ -Wall -Wextra -std=c++17 -o basic_flow basic_flow.cpp \
    -I../../../crates/pap-c/include \
    -L../../../target/release \
    -lpap_c

# Run
export LD_LIBRARY_PATH=../../../target/release
./basic_flow
```

On macOS:

```bash
g++ -Wall -Wextra -std=c++17 -o basic_flow basic_flow.cpp \
    -I../../../crates/pap-c/include \
    -L../../../target/release \
    -lpap_c \
    -framework CoreFoundation \
    -framework Security
```

## Development Workflow

### Modify pap.hpp

After editing `bindings/cpp/pap.hpp`:

```bash
cd bindings/cpp/build
cmake --build .           # Rebuilds without recompiling pap-c
```

### Modify examples

After editing examples:

```bash
cd bindings/cpp/build
cmake --build .           # Incremental rebuild
ctest --output-on-failure
```

### Modify C API (pap.h)

If you modify `crates/pap-c/src/lib.rs`, regenerate the C header:

```bash
cd pap
cargo build -p pap-c --release
# cbindgen regenerates crates/pap-c/include/pap.h automatically
```

Then rebuild C++ examples:

```bash
cd bindings/cpp/build
cmake --build .
```

## Verification

### Check compilation flags

```bash
cmake --build . -- VERBOSE
```

Look for `-Wall -Wextra` in the output.

### Check linker symbols

```bash
nm ./example_basic_flow | grep pap_keypair_generate
```

Should show a reference (U = undefined, defined in libpap_c).

### Run with debugging

```bash
gdb ./example_basic_flow
run
bt
quit
```

Or use Valgrind for memory analysis:

```bash
valgrind --leak-check=full ./example_basic_flow
```

All objects should be freed on exit (0 memory leaks).

## Advanced: Custom PAP_ROOT

If `libpap_c` is in a non-standard location:

```bash
cmake -DPAP_ROOT=/custom/path/to/repo ..
```

This tells CMake to search for `libpap_c` in `/custom/path/to/repo/target/release` and `/custom/path/to/repo/target/debug`.

## Windows (MSVC)

```bash
# Build pap-c
cd pap
cargo build -p pap-c --release

# Build examples
cd bindings\cpp
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 -DPAP_ROOT=..\.. ..
cmake --build . --config Release
ctest --output-on-failure -C Release
```

Binaries will be in `Release/` subfolder.
