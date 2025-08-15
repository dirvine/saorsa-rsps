# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Saorsa RSPS is a Rust crate implementing Root-Scoped Provider Summaries using Golomb Coded Sets (GCS) for efficient DHT lookups and cache management in P2P networks. The project focuses on space-efficient Content ID (CID) summaries with configurable false positive rates, designed specifically for decentralized network applications.

## Development Commands

### Building and Testing
```bash
# Build the project
cargo build

# Build with all features
cargo build --all-features

# Run all tests
cargo test

# Run tests with verbose output
cargo test --verbose

# Run tests for a specific module
cargo test cache
cargo test gcs
cargo test ttl
cargo test witness

# Run property tests (uses proptest)
cargo test proptest
```

### Code Quality
```bash
# Format code
cargo fmt

# Check format without making changes
cargo fmt -- --check

# Run clippy lints
cargo clippy

# Clippy with all targets and features (CI standard)
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit
```

### Benchmarks
```bash
# Run criterion benchmarks
cargo bench

# Run benchmarks with HTML reports
cargo bench --features bench
```

### Documentation
```bash
# Build and open local documentation
cargo doc --open

# Build docs for all dependencies
cargo doc --document-private-items --open
```

## Project Architecture

### Core Components

The crate is structured around five main modules:

1. **GCS (Golomb Coded Sets) - `src/gcs.rs`**
   - Implements space-efficient probabilistic data structures using Golomb-Rice coding
   - Enforces power-of-two parameters for deterministic encode/decode behavior
   - Key struct: `GolombCodedSet` with `GcsBuilder` for construction

2. **RSPS Core - `src/lib.rs`** 
   - Main `Rsps` struct representing Root-Scoped Provider Summaries
   - Links root CIDs with epochs and GCS summaries of child CIDs
   - Provides digest generation for DHT advertisement

3. **Cache Management - `src/cache.rs`**
   - `RootAnchoredCache` for hierarchical cache admission policies
   - Uses DashMap and LRU for concurrent cache operations
   - Implements cache policies based on root depth and pledge ratios

4. **TTL Engine - `src/ttl.rs`**
   - Sophisticated time-to-live management with hit tracking
   - TTL extension based on cache hits and witness receipts
   - Temporal bucketing for receipt aggregation

5. **Witness System - `src/witness.rs`**
   - VRF-based witness receipts for distributed verification
   - Currently uses placeholder cryptography (not production-ready)
   - Supports pseudonyms and reputation systems

6. **Crypto Module - `src/crypto/`**
   - Cryptographic primitives and types
   - Provider traits for signature and VRF operations
   - Uses ed25519-dalek, schnorrkel, and vrf-r255

### Data Flow

1. **Content Organization**: Content is organized hierarchically under root CIDs
2. **Summary Creation**: RSPS are built using GCS to summarize child CIDs under a root
3. **DHT Advertisement**: RSPS digests are published to the DHT keyed by root_cid+epoch
4. **Discovery**: Clients fetch RSPS and use `contains()` for probabilistic membership testing
5. **Cache Management**: Cache admission is controlled by RSPS membership and policies
6. **TTL Management**: Entry lifetimes are extended based on hits and witness receipts

### Key Design Decisions

- **Golomb-Rice Coding**: Uses power-of-two parameters for deterministic behavior
- **False Positive Rate**: Configurable target FPR (default 0.05%)
- **Async/Await**: Full Tokio integration for P2P network operations
- **Error Handling**: Uses `thiserror` for structured error types, no `unwrap()`/`expect()` in production
- **Security**: Cryptographically secure RNG, but witness crypto is placeholder only
- **Performance**: Optimized for memory efficiency and network bandwidth

## Key Types and Constants

```rust
// Core types
pub type Cid = [u8; 32];           // Content identifier
pub type RootCid = [u8; 32];       // Root identifier

// Main structs
pub struct Rsps { ... }             // Root-Scoped Provider Summary
pub struct GolombCodedSet { ... }   // Space-efficient set representation
pub struct RootAnchoredCache { ... } // Hierarchical cache
pub struct TtlEngine { ... }        // TTL management
```

## Configuration

Default configuration provides:
- Target FPR: 0.05% (5e-4)
- Base TTL: 2 hours
- TTL per hit: 30 minutes (max 12 hours)
- TTL per receipt: 10 minutes (max 2 hours)
- Receipt bucketing: 5 minutes

## Testing Strategy

- Unit tests for all public APIs
- Property-based testing using `proptest` for GCS operations
- Integration tests for cache and TTL behavior
- Benchmark tests using `criterion`
- No production code uses `unwrap()` or `expect()`

## Security Considerations

- The witness cryptography (VRF and signatures) is currently simplified and **NOT production-ready**
- GCS verification enforces Golomb-Rice coding parameters for security
- Uses cryptographically secure random number generation via `rand`
- AGPL-3.0 licensed

## CI/CD Pipeline

GitHub Actions workflow runs:
1. Format check (`cargo fmt -- --check`)
2. Clippy linting with strict warnings
3. All tests with verbose output
4. Security audit on PRs

## Dependencies

Key dependencies include:
- **Core**: `anyhow`, `thiserror`, `bytes`, `serde`, `bincode`
- **Crypto**: `blake3`, `sha2`, `ed25519-dalek`, `schnorrkel`, `vrf-r255`
- **Data Structures**: `bitvec`, `bitreader`, `lru`, `dashmap`, `parking_lot`
- **Async**: `tokio` with full features, `async-trait`
- **Testing**: `proptest`, `criterion`, `quickcheck`

## Common Development Patterns

When working with this codebase:
- Use `Result<T>` type alias instead of `std::result::Result<T, RspsError>`
- Follow the existing error handling patterns with `thiserror`
- Property tests should use `proptest` for probabilistic data structure validation
- Async functions use Tokio runtime
- All cryptographic operations should use secure RNG from `rand` crate
- GCS operations must validate power-of-two parameters