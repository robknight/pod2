//! Speeds up witness generation with plonky2's compiled witness executor (the
//! `witness_executor` feature).
//!
//! A proof needs a value for every wire of the circuit. The caller supplies the
//! inputs; the circuit's witness generators compute the rest, each reading some
//! wires and filling in others, in dependency order (MainPod's recursive
//! circuit has about 1.6 million). This runs on the CPU even when a GPU does
//! the rest of the proof, and it is CPU-bound: the arithmetic is cheap, and
//! plonky2's default worklist spends most of its time dispatching each
//! generator and merging its outputs.
//!
//! A witness program, compiled once per circuit, reduces each generator to a
//! typed operation over fixed slots, grouped into layers of independent
//! operations, so the executor runs tight parallel loops. It computes exactly
//! the worklist's witness, two to three times faster (MainPod: about 24 ms
//! against 60 ms on an Apple M4). See `plonky2::plonk::witness_program`.
//!
//! pod2 installs a program on each circuit's first proof in a process, compiled
//! from that proof's inputs (about 0.44 s for MainPod on an M4), so the feature
//! suits processes that prove many times. With `disk_cache`, programs are
//! stored, keyed by circuit digest and plonky2's witness program `FORMAT`, and
//! later processes load them; plonky2 checks the circuit, format and
//! generators' operations when loading. Programs are kept per process by
//! circuit digest.
//!
//! A circuit plonky2 cannot compile (lookup tables, or a generator without an
//! operation description) keeps the worklist. Proofs never fail because of this
//! module: any failure to compile, load or install is logged and the proof uses
//! the worklist.

use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::Instant,
};

use plonky2::{
    field::types::PrimeField64,
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{CircuitData, ProverCircuitData, ProverOnlyCircuitData},
        witness_program::{WitnessProgram, WitnessProgramError},
    },
};

use crate::middleware::{C, D, F};

/// Circuit data that can hold an installed witness program.
pub(crate) trait WitnessProgramHost {
    fn prover_only(&self) -> &ProverOnlyCircuitData<F, C, D>;
    fn has_witness_program(&self) -> bool;
    fn compile_like(&self, pw: &PartialWitness<F>) -> Result<WitnessProgram, WitnessProgramError>;
    #[cfg_attr(not(feature = "disk_cache"), allow(dead_code))]
    fn decode(&self, bytes: &[u8]) -> Result<WitnessProgram, WitnessProgramError>;
    fn install(&self, program: WitnessProgram) -> Result<(), WitnessProgramError>;
}

macro_rules! host {
    ($ty:ty) => {
        impl WitnessProgramHost for $ty {
            fn prover_only(&self) -> &ProverOnlyCircuitData<F, C, D> {
                &self.prover_only
            }
            fn has_witness_program(&self) -> bool {
                self.witness_program().is_some()
            }
            fn compile_like(
                &self,
                pw: &PartialWitness<F>,
            ) -> Result<WitnessProgram, WitnessProgramError> {
                self.compile_witness_program_like(pw)
            }
            fn decode(&self, bytes: &[u8]) -> Result<WitnessProgram, WitnessProgramError> {
                self.witness_program_from_bytes(bytes)
            }
            fn install(&self, program: WitnessProgram) -> Result<(), WitnessProgramError> {
                self.install_witness_program(program)
            }
        }
    };
}
host!(CircuitData<F, C, D>);
host!(ProverCircuitData<F, C, D>);

/// This process's program for each circuit digest; `None` for circuits
/// plonky2 cannot compile, so they are tried once per process.
static PROGRAMS: LazyLock<Mutex<HashMap<String, Option<WitnessProgram>>>> =
    LazyLock::new(Default::default);

fn digest_hex(prover: &ProverOnlyCircuitData<F, C, D>) -> String {
    prover
        .circuit_digest
        .elements
        .iter()
        .map(|e| format!("{:016x}", e.to_canonical_u64()))
        .collect()
}

/// Installs a witness program on `data` before a proof with inputs `pw`, if it
/// has none: loads it from the disk cache (with `disk_cache`), or compiles it
/// for `pw`'s targets.
/// Failures are logged and leave the worklist in place; they never fail the
/// proof.
pub(crate) fn ensure_installed(data: &impl WitnessProgramHost, pw: &PartialWitness<F>) {
    if data.has_witness_program() {
        return;
    }
    let digest = digest_hex(data.prover_only());
    let known = PROGRAMS.lock().unwrap().get(&digest).cloned();
    let started = Instant::now();
    let (program, source) = match known {
        Some(Some(program)) => (program, "kept"),
        Some(None) => return,
        None => match obtain(data, pw, &digest) {
            Some((program, source)) => {
                PROGRAMS
                    .lock()
                    .unwrap()
                    .insert(digest.clone(), Some(program.clone()));
                (program, source)
            }
            None => {
                PROGRAMS.lock().unwrap().insert(digest, None);
                return;
            }
        },
    };
    match data.install(program) {
        Ok(()) => log::debug!(
            "pod2: installed the witness program of circuit {digest} ({source}) in {:?}",
            started.elapsed()
        ),
        Err(error) => {
            log::warn!("pod2: circuit {digest}: witness program not installed: {error}")
        }
    }
}

/// Compiles a program for `pw`'s targets; `None` when plonky2 cannot.
fn compile(
    data: &impl WitnessProgramHost,
    pw: &PartialWitness<F>,
    digest: &str,
) -> Option<WitnessProgram> {
    match data.compile_like(pw) {
        Ok(program) => Some(program),
        Err(error) => {
            log::info!("pod2: circuit {digest} keeps the worklist witness: {error}");
            None
        }
    }
}

/// Without `disk_cache` every process compiles its own programs.
#[cfg(not(feature = "disk_cache"))]
fn obtain(
    data: &impl WitnessProgramHost,
    pw: &PartialWitness<F>,
    digest: &str,
) -> Option<(WitnessProgram, &'static str)> {
    compile(data, pw, digest).map(|program| (program, "compiled"))
}

#[cfg(feature = "disk_cache")]
fn obtain(
    data: &impl WitnessProgramHost,
    pw: &PartialWitness<F>,
    digest: &str,
) -> Option<(WitnessProgram, &'static str)> {
    use serde::{Deserialize, Serialize};

    /// Stored program bytes; empty for a circuit plonky2 cannot compile.
    #[derive(Serialize, Deserialize)]
    struct ProgramBytes(#[serde(with = "serde_bytes")] Vec<u8>);

    let mut compiled = None;
    let key = (digest.to_string(), plonky2::plonk::witness_program::FORMAT);
    // Transient: the bytes are decoded into the installed program and dropped.
    let stored = crate::cache::get_transient("witness_program", &key, |_| {
        let program = compile(data, pw, digest);
        let bytes = program.as_ref().map(|p| p.to_bytes()).unwrap_or_default();
        compiled = Some(program);
        ProgramBytes(bytes)
    });
    if let Some(program) = compiled {
        return program.map(|program| (program, "compiled and stored"));
    }
    let stored = match stored {
        Ok(stored) => stored,
        Err(error) => {
            log::warn!("pod2: circuit {digest}: witness program cache failed: {error}");
            return compile(data, pw, digest).map(|program| (program, "compiled"));
        }
    };
    if stored.0.is_empty() {
        return None;
    }
    match data.decode(&stored.0) {
        Ok(program) => Some((program, "loaded")),
        Err(error) => {
            // Same format but other operations: a generator changed without a
            // new pod2 commit (for example a patched dependency). Correct but
            // slow, since the entry is not replaced.
            log::warn!(
                "pod2: circuit {digest}: stored witness program rejected ({error}); compiling"
            );
            compile(data, pw, digest).map(|program| (program, "compiled"))
        }
    }
}
