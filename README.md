# Saorsa RSPS

[![Rust](https://github.com/dirvine/saorsa-rsps-foundation/actions/workflows/rust.yml/badge.svg)](https://github.com/dirvine/saorsa-rsps-foundation/actions/workflows/rust.yml)
[![docs.rs](https://docs.rs/saorsa-rsps/badge.svg)](https://docs.rs/saorsa-rsps)
[![Crates.io](https://img.shields.io/crates/v/saorsa-rsps.svg)](https://crates.io/crates/saorsa-rsps)

Root-Scoped Provider Summaries using Golomb Coded Sets (GCS) for efficient DHT lookups and cache management in P2P networks.

## Features

- **Golomb Coded Sets**: Space-efficient Content ID (CID) summaries with configurable false positive rates
- **Root-anchored Cache**: Cache admission policies anchored to root CIDs for hierarchical data organization
- **TTL Management**: Sophisticated time-to-live management with hit tracking and witness receipts
- **VRF Pseudonyms**: Verifiable Random Function pseudonyms for witness receipt systems
- **Async/Await Support**: Full async/await support with Tokio
- **High Performance**: Optimized for P2P DHT operations with minimal memory overhead

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
saorsa-rsps = "0.1.0"
```

## Example Usage

```rust
use saorsa_rsps::{Rsps, RspsConfig, Cid};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root_cid = [1u8; 32];
    let cids = vec![
        [2u8; 32],
        [3u8; 32],
        [4u8; 32],
    ];
    let config = RspsConfig::default();
    
    // Create RSPS for a root with associated CIDs
    let rsps = Rsps::new(root_cid, 1, &cids, &config)?;
    
    // Check if a CID might be under this root
    let test_cid = [2u8; 32];
    if rsps.contains(&test_cid) {
        println!("CID might be under this root");
    }
    
    // Get digest for DHT advertisement
    let digest = rsps.digest();
    println!("RSPS digest: {:?}", digest);
    
    Ok(())
}
```

## Components

### Golomb Coded Sets (GCS)
Efficient probabilistic data structure for representing sets with configurable false positive rates. Optimized for P2P networks where bandwidth and storage efficiency are critical.

### Cache Management
Root-anchored cache policies that organize data hierarchically under root CIDs, with sophisticated TTL management based on hit frequency and witness receipts.

### TTL Engine
Advanced time-to-live management with:
- Base TTL for new entries
- TTL extension per cache hit
- TTL extension per witness receipt
- Temporal bucketing for receipt aggregation

### Witness System
VRF-based witness receipts for distributed verification and reputation systems in P2P networks.

## Architecture

RSPS (Root-Scoped Provider Summaries) organize content hierarchically under root CIDs, enabling efficient DHT lookups for complex data structures. Each RSPS contains:

- **Root CID**: The anchor point for hierarchical organization
- **Epoch**: Version/time identifier for cache invalidation
- **GCS**: Space-efficient summary of CIDs under this root
- **Salt**: Deterministic salt for GCS construction
- **Metadata**: Creation timestamp and configuration

## Performance

Saorsa RSPS is optimized for:
- **Memory Efficiency**: GCS provides space-efficient CID summaries
- **Network Efficiency**: Minimal bandwidth for DHT advertisements
- **Lookup Speed**: Fast probabilistic membership testing
- **Cache Effectiveness**: Smart TTL management with hit tracking

## Safety and Security

- Built with Rust 2024 edition for memory safety
- No `unwrap()` or `expect()` in production code
- Comprehensive error handling with `thiserror`
- Security audit workflow with `cargo-audit`
- Cryptographically secure random number generation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL-3.0 license. See [LICENSE](LICENSE) for details.

## Related Projects

- [saorsa-fec](https://github.com/dirvine/saorsa-foundation) - Patent-free erasure coding
- [saorsa-core](https://github.com/maidsafe/p2p) - P2P networking foundation