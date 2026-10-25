//! Optional compiled witness generation, prepared through plonky2's public API.
//!
//! POD2 requests preparation on first use, or during `mainpod::prepare`.
//! plonky2 owns compilation, persistent executor caching, validation and host
//! preparation. `PLONKY2_EXECUTOR_CACHE_DIR` enables its cache independently of
//! POD2's `disk_cache`, which still owns circuit data and padding proofs.
//!
//! Environment defaults work without a POD2 configuration wrapper. Applications
//! needing programmatic resource control may call `configure_witness_executor`
//! before preparation/proving. Unsupported generators keep the worklist under
//! the default fallback policy; invalid configuration and unexpected preparation
//! errors are returned to the caller. Strict fallback also rejects unsupported
//! circuits, so it cannot silently change latency on a later proof.
use std::sync::Mutex;

use plonky2::{
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_data::{CircuitData, ProverCircuitData},
        witness_program::{
            WitnessConfig, WitnessFallback, WitnessPreparation, WitnessProgramError,
            WitnessProgramStatus,
        },
    },
};

use crate::middleware::{C, D, F};

#[derive(Default)]
struct Settings {
    config: Option<WitnessConfig>,
    started: bool,
}
static SETTINGS: Mutex<Settings> = Mutex::new(Settings {
    config: None,
    started: false,
});

/// Set process-wide witness settings before the first preparation/proof.
/// Environment defaults are used when this is not called. A caller-owned Rayon
/// pool in `config` can be shared by every circuit. Later changes are rejected
/// because POD2 caches and shares prepared circuit data within the process.
pub fn configure(config: WitnessConfig) -> anyhow::Result<()> {
    SETTINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .configure(config)
}
fn configuration() -> Result<WitnessConfig, WitnessProgramError> {
    SETTINGS.lock().unwrap_or_else(|e| e.into_inner()).resolve()
}

impl Settings {
    fn configure(&mut self, config: WitnessConfig) -> anyhow::Result<()> {
        config.validate()?;
        anyhow::ensure!(
            !self.started,
            "POD2 witness executor settings must be configured before preparation or proving"
        );
        self.config = Some(config);
        Ok(())
    }
    fn resolve(&mut self) -> Result<WitnessConfig, WitnessProgramError> {
        if self.config.is_none() {
            self.config = Some(WitnessConfig::from_env()?);
        }
        self.started = true;
        Ok(self
            .config
            .as_ref()
            .expect("initialized witness configuration")
            .clone())
    }
}

pub(crate) trait WitnessProgramHost {
    fn status(&self) -> WitnessProgramStatus;
    fn prepare(
        &self,
        targets: &[Target],
        config: WitnessConfig,
    ) -> Result<WitnessPreparation, WitnessProgramError>;
}
macro_rules! host {
    ($ty:ty) => {
        impl WitnessProgramHost for $ty {
            fn status(&self) -> WitnessProgramStatus {
                self.witness_program_status()
            }
            fn prepare(
                &self,
                targets: &[Target],
                config: WitnessConfig,
            ) -> Result<WitnessPreparation, WitnessProgramError> {
                self.prepare_witness_program_with_config(targets, config)
            }
        }
    };
}
host!(CircuitData<F,C,D>);
host!(ProverCircuitData<F,C,D>);

pub(crate) fn ensure_installed(
    data: &impl WitnessProgramHost,
    pw: &PartialWitness<F>,
) -> anyhow::Result<()> {
    let status = data.status();
    if status == WitnessProgramStatus::Ready {
        return Ok(());
    }
    ensure_with_config(data, pw, status, configuration()?)
}
fn ensure_with_config(
    data: &impl WitnessProgramHost,
    pw: &PartialWitness<F>,
    status: WitnessProgramStatus,
    config: WitnessConfig,
) -> anyhow::Result<()> {
    let required = config.fallback == WitnessFallback::Error;
    // A memoized unsupported circuit returns before inspecting targets. Avoid
    // allocating/copying a large input schema for every subsequent proof.
    let targets = if status == WitnessProgramStatus::Unsupported {
        Vec::new()
    } else {
        pw.target_values.keys().copied().collect()
    };
    match data.prepare(&targets, config) {
        Ok(prepared) => {
            log::debug!("POD2 witness executor {:?}, ready in {:?} (read {:?}, compile {:?}, write {:?}, host {:?})",prepared.source,prepared.elapsed,prepared.cache_read,prepared.compile,prepared.cache_write,prepared.host_prepare);
            Ok(())
        }
        Err(error)
            if !required
                && matches!(
                    error,
                    WitnessProgramError::UnsupportedField
                        | WitnessProgramError::Lookups
                        | WitnessProgramError::UnsupportedGenerator { .. }
                ) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Unsupported;
    impl WitnessProgramHost for Unsupported {
        fn status(&self) -> WitnessProgramStatus {
            WitnessProgramStatus::Unsupported
        }
        fn prepare(
            &self,
            targets: &[Target],
            _: WitnessConfig,
        ) -> Result<WitnessPreparation, WitnessProgramError> {
            assert!(targets.is_empty());
            Err(WitnessProgramError::UnsupportedGenerator {
                index: 0,
                id: "application generator".into(),
            })
        }
    }
    #[test]
    fn unsupported_generators_fall_back_unless_compiled_execution_is_required() {
        let inputs = PartialWitness::new();
        let status = WitnessProgramStatus::Unsupported;
        ensure_with_config(&Unsupported, &inputs, status, WitnessConfig::default()).unwrap();
        let mut config = WitnessConfig::default();
        config.fallback = WitnessFallback::Error;
        assert!(ensure_with_config(&Unsupported, &inputs, status, config)
            .unwrap_err()
            .to_string()
            .contains("application generator"));
    }
    #[test]
    fn resource_configuration_is_fixed_before_the_first_preparation() {
        let mut settings = Settings::default();
        let mut config = WitnessConfig::default();
        config.buffers = plonky2::plonk::witness_program::WitnessBuffers::Reuse { max_bytes: 1024 };
        settings.configure(config.clone()).unwrap();
        assert_eq!(settings.resolve().unwrap().buffers, config.buffers);
        assert!(settings
            .configure(WitnessConfig::default())
            .unwrap_err()
            .to_string()
            .contains("before preparation"));
        let mut fresh = Settings::default();
        let mut invalid = WitnessConfig::default();
        invalid.chain_length = 1;
        assert!(fresh.configure(invalid).is_err());
        assert!(!fresh.started);
    }
}
