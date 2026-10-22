# POD2

## Usage
- Run tests: `cargo test --release`
- Rustfmt: `cargo fmt`
- Check [typos](https://github.com/crate-ci/typos): `typos -c .github/workflows/typos.toml`

## GPU proving
pod2 uses the GPU fork of plonky2 ([robknight/plonky2](https://github.com/robknight/plonky2/tree/gpu)), which adds GPU proving through wgpu without changing proofs, circuit data or the verifier (see its [docs/gpu.md](https://github.com/robknight/plonky2/blob/gpu/docs/gpu.md)). With the `gpu` feature, proofs run on a GPU when one is usable (Metal, Vulkan or DirectX 12, chosen at run time) and on the CPU otherwise; configure it with `plonky2::gpu::configure` before the first proof if the defaults do not suit, for example for several concurrent proofs. `gpu-profiling` adds plonky2's GPU diagnostics.

## Faster witness generation
With `witness_executor`, witnesses are generated with plonky2's compiled witness executor instead of its worklist, two to three times faster; this needs the fork of plonky2-u32 ([robknight/plonky2-u32](https://github.com/robknight/plonky2-u32/tree/gpu)) as well. Each circuit's program is compiled on its first proof in a process (about 0.4 s for MainPod on an Apple M4), so this suits processes that prove many times; with `disk_cache` the programs are stored and later processes load them.

`backends::plonky2::mainpod::prepare(&params, &vd_set)` builds and caches everything MainPod proofs need (circuits, the padding EmptyPod and, with `witness_executor`, the witness program), so an application can pay those costs at startup instead of on its first proof.

`cargo run --release --features gpu,witness_executor --example mainpod_prove -- --prepare --proofs 4` proves and times MainPods (`--help` for options).

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
