# POD2

## Usage
- Run tests: `cargo test --release`
- Rustfmt: `cargo fmt`
- Check [typos](https://github.com/crate-ci/typos): `typos -c .github/workflows/typos.toml`

## GPU proving
pod2 uses the GPU fork of plonky2 ([robknight/plonky2](https://github.com/robknight/plonky2/tree/gpu)), which adds GPU proving through wgpu without changing proofs, circuit data or the verifier (see its [docs/gpu.md](https://github.com/robknight/plonky2/blob/gpu/docs/gpu.md)). With the `gpu` feature, proofs run on a GPU when one is usable (Metal, Vulkan or DirectX 12, chosen at run time) and on the CPU otherwise; configure it with `plonky2::gpu::configure` before the first proof if the defaults do not suit, for example for several concurrent proofs. `gpu-profiling` adds plonky2's GPU diagnostics.

## Faster witness generation
With `witness_executor`, POD2 prepares plonky2's compiled witness executor for each circuit before its first proof. The measured fast defaults apply automatically. The plonky2-u32 fork must describe its comparison generator's witness operation; unsupported circuits use the ordinary worklist by default.

Ready-chunk dependency scheduling and hardware-eligible Poseidon batching are automatic. Portable x86 builds detect AVX-512 support at runtime; other machines retain the scalar path. No circuit-specific generated Rust or external compiler is required. `WitnessSchedule::Layers` and `WitnessPoseidon::Scalar` are available for comparisons through the re-exported configuration API.

Set `PLONKY2_EXECUTOR_CACHE_DIR` to enable compiled-executor caching across processes. plonky2 owns identity, validation, loading, compilation, atomic replacement and concurrent preparation. This does not require POD2's `disk_cache` feature. That separate feature still caches POD2 circuit data and padding proofs.

`backends::plonky2::mainpod::prepare(&params, &vd_set)` prepares the circuit, padding proof and witness executor before accepting proof requests. Host executor tables are initialized before it returns. Measure total preparation and first-proof time as well as warm proof time.

Applications can use documented `PLONKY2_EXECUTOR_*` process defaults without forwarding backend-specific fields through POD2. For programmatic resource control, call `backends::plonky2::configure_witness_executor(WitnessConfig)` before the first preparation or proof. The relevant configuration types are re-exported there. A caller-owned Rayon pool can be shared across circuits. POD2 shares cached circuit data within a process, so configuration changes after preparation are rejected. Invalid settings and unexpected preparation errors are returned; cache I/O failures allow memory-only preparation. `WitnessFallback::Error` requires compiled execution, including rejecting unsupported circuits.

```sh
PLONKY2_EXECUTOR_CACHE_DIR=/var/cache/my-app/executors cargo run --release --features gpu,witness_executor --example mainpod_prove -- --prepare --proofs 4
```

See plonky2's `docs/witness-executor.md` for configuration, resource ownership, compatibility, custom-generator checks and the explicit preparation API.

## Book
The `book` contains the specification of POD2. A rendered version of the site can be found at: https://0xparc.github.io/pod2/

To run it locally:
- Requirements
	- [mdbook](https://github.com/rust-lang/mdBook): `cargo install mdbook`
	- [mdbook-katex](https://github.com/lzanini/mdbook-katex): `cargo install mdbook-katex`
- Go to the book directory: `cd book`
- Run the mdbook: `mdbook serve`

## License

MIT
