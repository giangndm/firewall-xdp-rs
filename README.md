# Software Defined Firewall with Rust and eBpf-XDP

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```

## Architecture

Userspace application will manage blacklist and whitelist ip in a map: BLACKLIST and WHITELIST. eBpf program will using that map for checking BLACKLIST or WHITELIST

The list can be updated by some ways
- API and token
- Config file and dynamic reload by send POST to api/reload_config


### BLACKLIST map

In this version each 

### WHITELIST map

