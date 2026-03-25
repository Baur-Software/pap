# PAP C++ Header-Only Wrapper Examples

Runnable examples demonstrating the Principal Agent Protocol C++ RAII wrapper (`pap.hpp`). All examples compile with `-Wall -Wextra` on Clang 16+ and GCC 13+.

## Quick Start

### Build

```bash
cd pap/bindings/cpp
mkdir -p build && cd build
cmake -DPAP_ROOT=../../.. ..
cmake --build .
ctest --output-on-failure
```

### Run Individual Examples

```bash
# Mandate → Session → Receipt flow
./example_basic_flow

# RAII destructors and error handling
./example_raii_and_errors

# Multi-hop delegation with scope narrowing
./example_delegation_chain
```

## Examples

### 1. `basic_flow.cpp` — Complete Protocol Flow

Demonstrates the entire PAP protocol from keypair generation through session closure:

- **Key generation**: Principal and agent Ed25519 keypairs
- **Scope & disclosure**: Define permitted actions and information sharing
- **Mandate issuance & signing**: Principal creates and signs root mandate
- **Decay states**: Inspect and sync mandate TTL-based decay (Active → Degraded → ReadOnly → Suspended)
- **Serialization**: Mandate to JSON and back with verification
- **Capability token**: Ephemeral single-use proof for session initiation
- **Session state machine**: Initiated → Open → Executed → Closed
- **RAII cleanup**: Automatic destructor cleanup on scope exit

**Runtime output:**
- Displays DIDs, mandate hashes, session IDs
- Shows decay state transitions
- Verifies all serialization round-trips
- Confirms all RAII destructors invoked

### 2. `raii_and_errors.cpp` — RAII & Error Handling

Validates RAII patterns and exception safety with 10 focused tests:

1. **Keypair move semantics** — Move construct and move assign without double-free
2. **Scope cleanup with exception** — Objects destroyed even when exceptions thrown
3. **Mandate lifecycle** — Full lifecycle including move assignment
4. **Nested scope cleanup** — Multiple objects cleaned up in reverse order
5. **Error handling** — Invalid JSON throws `PapException`
6. **Session state machine** — State transitions validated (Initiated → Open → Executed → Closed)
7. **Decay state management** — Active → Degraded → ReadOnly → Suspended transitions
8. **DID utilities** — Extract public key from `did:key` format
9. **Serialization round-trip** — JSON serialize/deserialize/verify cycle
10. **Scope containment** — Broad scope contains narrow scope subset

All tests verify that destructors are called automatically, with zero manual cleanup required.

### 3. `delegation_chain.cpp` — Multi-Hop Delegation

Demonstrates mandate delegation with scope narrowing across multiple agents:

- **Principal → Agent1 (root mandate)** with broad scope (Search, Reserve, Payment)
- **Agent1 → Agent2 (delegation)** with narrowed scope (Search, Reserve only)
- **Chain verification** — Inspect issuer/agent/principal relationships
- **Scope narrowing** — Verify broad scope contains narrow scope
- **Decay states** — Both mandates remain Active
- **Serialization** — JSON round-trip for delegated mandates
- **Session creation** — Initiate session with delegated authority
- **Verification** — Each mandate verified with issuer's public key

Showcases how the protocol maintains cryptographic chain-of-custody through multiple hops while enforcing scope narrowing.

## Architecture

### RAII Wrapper Classes

All PAP types use RAII (Resource Acquisition Is Initialization):

```cpp
// No manual cleanup needed
{
    auto kp = pap::PrincipalKeypair::generate();  // Acquired
    auto scope = pap::Scope::from({...});         // Acquired
    auto mandate = pap::Mandate::issue_root(...); // Acquired

    // Use objects here
    mandate.sign(kp);

} // Destructors called automatically, C layer freed
```

**No copy semantics** — Types are move-only to prevent accidental double-frees:

```cpp
pap::Mandate m1 = ...;
pap::Mandate m2 = m1;         // Compile error: deleted copy constructor
pap::Mandate m2 = std::move(m1); // OK: move assignment
```

### Error Handling

All operations throw `pap::PapException` on failure (C layer returns -1 or NULL):

```cpp
try {
    auto mandate = pap::Mandate::from_json(invalid_json);
} catch (const pap::PapException& e) {
    std::cerr << "PAP error: " << e.what() << "\n";
}
```

The wrapper automatically:
- Calls `pap_last_error_message()` on failure
- Frees returned C strings with `pap_string_free()`
- Throws with descriptive context

## Compilation Details

### Flags

Examples compile with strict warnings:

- `-Wall -Wextra -Wpedantic` on GCC/Clang
- `/W4` on MSVC

No warnings in either the examples or `pap.hpp`.

### Supported Compilers

- **GCC 13+** (GNU C++ standard library)
- **Clang 16+** (libc++ or libstdc++)
- **MSVC 2019+** (Windows)

### Linking

Each example links:
- `libpap_c` (compiled from `crates/pap-c`)
- On macOS: `-framework CoreFoundation -framework Security` (via libpap_c dependency on `ring`)

CMake automatically locates these via:

```cmake
find_library(PAP_C_LIB NAMES pap_c
    HINTS "${PAP_ROOT}/target/release"
          "${PAP_ROOT}/target/debug")
```

## Testing

All examples double as integration tests via CMake/ctest:

```bash
cmake --build . && ctest --output-on-failure
```

Each example:
- Demonstrates a complete PAP workflow
- Validates invariants (assertions)
- Verifies RAII cleanup (implicit via no crashes or leaks)
- Returns 0 on success, 1 on failure

Tests can be run with `ctest -V` for verbose output or individually:

```bash
./example_raii_and_errors  # Prints 10 test results
```

## Memory Safety

The C++ wrapper guarantees:

1. **No manual cleanup** — Destructors automatically free C layer allocations
2. **No double-frees** — Move-only semantics prevent accidental reuse
3. **No leaks on exceptions** — RAII cleanup happens on stack unwind
4. **Safe move** — Moved-from objects hold null pointers, safe to destroy

Example: Exception during mandate signing still cleans up scope and session:

```cpp
try {
    auto scope = pap::Scope::from(...);         // Allocated
    auto mandate = pap::Mandate::issue_root(...); // Allocated
    mandate.sign(invalid_keypair);              // Throws PapException
} catch (...) {
    // scope and mandate destructors called
    // All C allocations freed
}
```

## File Layout

```
bindings/cpp/
├── pap.hpp                      # Header-only wrapper (18KB)
├── CMakeLists.txt               # Top-level: includes examples subdir
└── examples/
    ├── CMakeLists.txt           # Example build config
    ├── basic_flow.cpp           # Full protocol demo
    ├── raii_and_errors.cpp      # RAII & error validation (10 tests)
    ├── delegation_chain.cpp     # Multi-hop delegation
    └── README.md                # This file
```

## Integration

To use `pap.hpp` in your own C++ project:

1. Copy `pap.hpp` to your project
2. Add include path: `-I/path/to/pap/bindings/cpp`
3. Add include path: `-I/path/to/pap/crates/pap-c/include`
4. Link `libpap_c`: `-L/path/to/pap/target/release -lpap_c`
5. Link macOS frameworks if needed (handled by CMake in these examples)

Example CMakeLists.txt:

```cmake
find_library(PAP_C_LIB pap_c REQUIRED)
add_executable(myapp main.cpp)
target_include_directories(myapp PRIVATE
    /path/to/pap/bindings/cpp
    /path/to/pap/crates/pap-c/include)
target_link_libraries(myapp PRIVATE ${PAP_C_LIB})
```

## References

- **PAP Specification**: [`docs/specification.md`](../../docs/specification.md)
- **C API**: [`crates/pap-c/include/pap.h`](../../crates/pap-c/include/pap.h)
- **C++ Wrapper**: [`pap.hpp`](../pap.hpp)
