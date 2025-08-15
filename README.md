# Saorsa RSPS

[![Rust](https://github.com/dirvine/saorsa-rsps-foundation/actions/workflows/rust.yml/badge.svg)](https://github.com/dirvine/saorsa-rsps-foundation/actions/workflows/rust.yml)
[![docs.rs](https://docs.rs/saorsa-rsps/badge.svg)](https://docs.rs/saorsa-rsps)
[![Crates.io](https://img.shields.io/crates/v/saorsa-rsps.svg)](https://crates.io/crates/saorsa-rsps)

Root-Scoped Provider Summaries using Golomb Coded Sets (GCS) for efficient DHT lookups and cache management in P2P networks.

## What This Solves

In decentralized networks like IPFS, BitTorrent, and other DHT-based P2P systems, finding content is expensive. Traditional approaches require:

- **Broadcasting provider records** for every piece of content to the entire DHT network, consuming massive bandwidth
- **Flooding the network** with discovery requests when searching for related content 
- **Storing individual provider records** for millions of Content IDs (CIDs), overwhelming DHT nodes with storage and lookup overhead

**Saorsa RSPS** solves this by introducing **hierarchical content organization** with **ultra-compact summaries**:

### The Problem: DHT Provider Record Explosion
When you store a large dataset (like a website, software repository, or media collection) in a P2P network, each file chunk gets its own CID. A typical website might have thousands of CIDs, a software repository tens of thousands. Publishing provider records for each CID individually to the DHT:
- Creates **millions of DHT messages** for large content
- **Overwhelms DHT nodes** with storage requirements  
- Makes **content discovery slow** due to network-wide searches
- **Wastes bandwidth** with redundant provider advertisements

### The Solution: Root-Scoped Provider Summaries
Instead of advertising individual CIDs, RSPS lets you:

1. **Group related content** under a single "root CID" (like a directory, repository, or collection)
2. **Create a compact summary** using Golomb Coded Sets that represents thousands of CIDs in just a few KB
3. **Advertise only the summary** to the DHT, reducing messages by 1000x or more
4. **Enable fast batch discovery** - one lookup tells you if ANY of thousands of CIDs might be available

### Real-World Use Cases

- **Content Distribution**: Efficiently advertise that you host an entire website/app without flooding the DHT
- **Software Repositories**: Let peers discover if you have specific versions/packages without individual lookups
- **Media Collections**: Advertise entire albums, movie series, or dataset collections as single summaries
- **Version Control**: Organize git-like repositories with hierarchical content discovery
- **Caching Networks**: Smart cache admission - only cache content that's part of advertised collections

### Performance Benefits

- **20-30% more compact** than Bloom filters for the same false positive rate
- **1000x reduction** in DHT provider record messages for large content collections
- **Sub-millisecond membership testing** for thousands of CIDs
- **Minimal memory overhead** - entire summaries fit in L1 cache
- **Network-efficient serialization** - summaries transport in single UDP packets

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

## Using RSPS in a Decentralized Network

This crate is designed for use in DHT-based or gossip-based networks where providers advertise summaries of content clustered under a root CID. A typical flow:

1. **Producer builds RSPS**
   - Select a `root_cid` and gather the set of child CIDs.
   - Build an `Rsps` with an epoch representing the dataset version.
   - Serialize or extract the `digest()` for lightweight advertisement in the DHT.

2. **Advertisement**
   - Publish either the RSPS bytes or its `digest` keyed by `root_cid`+`epoch` in your routing layer.
   - Peers cache the announcement, possibly with TTL heuristics matching their local policy.

3. **Discovery**
   - A client looking for a `cid` first fetches the RSPS for the relevant `root_cid`/`epoch`.
   - Use `rsps.contains(&cid)` to check probabilistic membership.
   - On positive result, proceed to fetch the content from providers under that root.

4. **Cache integration**
   - Register an `Rsps` with `RootAnchoredCache` to gate cache admission: only items in the RSPS are eligible.
   - Use the `TtlEngine` to manage lifetimes based on hits and witness receipts.

5. **Epoch rotation**
   - When the dataset changes, increment `epoch` and republish a new RSPS.
   - Consumers prefer the highest known epoch and drop stale ones per policy.

### False-positive tuning

- `RspsConfig.target_fpr` sets the target false positive rate. This crate uses Golomb–Rice coding internally, selecting a `p = 2^k` consistent with the requested FPR.
- Trade-offs:
  - Lower FPR → larger RSPS, more CPU to encode/decode, less cache pollution.
  - Higher FPR → smaller RSPS, faster, but occasional extra fetches.

### Why Golomb–Rice coding?

Golomb coding represents non-negative integers as a quotient (unary-coded) and a remainder (binary-coded) with respect to a parameter `p`. When `p` is a power of two (`p = 2^k`), the scheme is called Golomb–Rice coding. We choose Rice coding for RSPS because:

- Simpler and faster decode: the remainder is exactly `k = log2(p)` bits; no truncated-binary logic is needed, which keeps parsing branch-light and cache-friendly.
- Deterministic footprint vs. FPR: we pick `k = ceil(log2(1 / target_fpr))` so the parameter ties directly to the requested false-positive rate.
- Good practical compression for hashed, near-uniform deltas: the sorted hashed values modulo `n * p` produce geometric-like deltas that Rice handles efficiently.

In this crate, we enforce Rice coding by deriving `p` as a power of two and validating `p` during decode. This provides predictable encode/decode behavior and avoids edge cases that arise with general Golomb parameters.
### Serialization and transport

- `GolombCodedSet::to_bytes`/`from_bytes` serialize the GCS; an RSPS can be reconstructed from its components across nodes.
- For transport, include: `root_cid`, `epoch`, `salt`, and `gcs.to_bytes()`.

### Witness receipts

- Nodes can issue witness receipts for successful retrievals under a root to extend TTLs and inform reputation systems.
- Uses production-ready ed25519-dalek v2 for signatures and RFC 9381 ECVRF on ristretto255 for VRF pseudonyms.
- Implements domain separation to prevent cross-protocol attacks.

## Security Notes

### Cryptographic Implementation
- **Ed25519 signatures**: Uses `ed25519-dalek` v2.x, a battle-tested, misuse-resistant implementation
- **VRF pseudonyms**: RFC 9381 compliant ECVRF on ristretto255 via `vrf-r255` crate
- **Domain separation**: All cryptographic operations use distinct domain prefixes:
  - VRF inputs: `b"saorsa-rsps:vrf:v1:"`
  - Witness signatures: `b"saorsa-rsps:witness:v1:"`
- **Key hygiene**: Secret keys are automatically zeroized on drop
- **Separate key domains**: Ed25519 and VRF keys are kept completely separate

### Security Properties
- **No panics**: All cryptographic operations return `Result` types with proper error handling
- **Strict validation**: Input validation for all key sizes and proof lengths
- **Memory safety**: Built with Rust 2024 edition, `#![forbid(unsafe_code)]` in crypto module
- **Audit trail**: Uses well-audited cryptographic libraries with extensive test coverage

### Implementation Notes
- GCS uses Golomb–Rice coding (power-of-two parameter) to ensure decode correctness and performance
- VRF keys are separate from Ed25519 signature keys (different ciphersuites)
- Domain separation prevents attacks where signatures/proofs from one context are replayed in another
- All cryptographic operations are deterministic for the same inputs

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