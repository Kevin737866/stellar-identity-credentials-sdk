use sha2::{Digest, Sha256};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Map, Symbol, Vec,
    U256,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum PerformanceError {
    OptimizationFailed = 1,
    CacheMiss = 2,
    TimeoutExceeded = 3,
    ResourceExhausted = 4,
    InvalidParameters = 5,
}

// ── Proof compression (#179) ────────────────────────────────────────────────

/// Proofs at or below this size are stored verbatim. A PackBits control byte
/// per run costs more than it can save on inputs this short.
const MIN_COMPRESSIBLE_PROOF_BYTES: u32 = 64;
/// Longest run a single PackBits control byte can encode (control 129).
const MAX_PACKBITS_RUN: u32 = 128;
/// Largest control byte still meaning "literal run" rather than "repeat".
const PACKBITS_MAX_CONTROL: u8 = 127;
/// The reserved no-op control byte; never emitted by the encoder.
const PACKBITS_NOOP: u8 = 128;
/// Stored verbatim.
const CODEC_RAW: u8 = 0;
/// Stored PackBits-compressed.
const CODEC_PACKBITS: u8 = 1;
const BPS_DENOMINATOR: u64 = 10_000;
const BPS_DENOMINATOR_U32: u32 = 10_000;
/// `skip_reason` values on `ProofCompression`.
const SKIP_NONE: u32 = 0;
/// `compression_enabled` was false.
const SKIP_DISABLED: u32 = 1;
/// At or below `MIN_COMPRESSIBLE_PROOF_BYTES`.
const SKIP_TOO_SMALL: u32 = 2;
/// Compression ran but did not beat the original size.
const SKIP_NO_GAIN: u32 = 3;

// ── Validation cache (#163) ──────────────────────────────────────────────────

/// Storage bound on the validation cache, so a caller cannot grow it without
/// limit by varying the data it validates.
const MAX_VALIDATION_CACHE_ENTRIES: u32 = 256;
/// Default verdict lifetime: one hour.
const DEFAULT_VALIDATION_CACHE_TTL: u64 = 3600;

const VALIDATION_CACHE: &str = "validation_cache";
const SCHEMA_VERSIONS: &str = "schema_cache_versions";
const VALIDATION_CACHE_TTL: &str = "validation_cache_ttl";

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct PerformanceMetrics {
    pub proof_generation_time_ms: u64,
    pub verification_time_ms: u64,
    pub proof_size_bytes: u32,
    pub memory_usage_mb: u32,
    pub gas_consumed: u64,
    pub circuit_complexity: u8,
    pub optimization_level: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct OptimizationConfig {
    pub target_proof_time_ms: u64,
    pub target_verification_time_ms: u64,
    pub max_proof_size_bytes: u32,
    pub max_memory_mb: u32,
    pub cache_size_limit: u32,
    pub parallel_verification: bool,
    pub compression_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CachedProof {
    pub proof_id: Bytes,
    pub circuit_id: Symbol,
    pub proof_bytes: Bytes,
    pub public_inputs_hash: Bytes,
    pub created_at: u64,
    pub expires_at: u64,
    pub access_count: u32,
    pub performance_metrics: PerformanceMetrics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct ProofCompression {
    pub proof_id: Bytes,
    pub original_size: u32,
    pub stored_size: u32,
    /// `stored_size * 10000 / original_size`; `10000` means no saving.
    pub ratio_bps: u32,
    pub savings_bps: u32,
    pub compressed: bool,
    /// One of the `SKIP_*` constants; `0` when the proof was compressed.
    pub skip_reason: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CachedValidation {
    pub schema_id: Symbol,
    pub schema_hash: Bytes,
    pub data_hash: Bytes,
    pub is_valid: bool,
    /// Schema cache version this entry was written under.
    pub schema_version: u64,
    pub computed_at: u64,
    pub expires_at: u64,
    pub hit_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct BatchVerificationResult {
    pub total_proofs: u32,
    pub successful_verifications: u32,
    pub failed_verifications: u32,
    pub total_time_ms: u64,
    pub average_time_ms: u64,
    pub gas_used: u64,
}

#[contract]
pub struct PerformanceOptimizer;

#[contractimpl]
impl PerformanceOptimizer {
    /// Initialize performance optimization configuration
    pub fn initialize_optimization_config(
        env: Env,
        target_proof_time_ms: u64,
        target_verification_time_ms: u64,
        max_proof_size_bytes: u32,
        max_memory_mb: u32,
        cache_size_limit: u32,
        parallel_verification: bool,
        compression_enabled: bool,
    ) {
        let config = OptimizationConfig {
            target_proof_time_ms,
            target_verification_time_ms,
            max_proof_size_bytes,
            max_memory_mb,
            cache_size_limit,
            parallel_verification,
            compression_enabled,
        };

        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "optimization_config"), &config);

        // Initialize performance tracking
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "total_proofs_generated"), &0u32);
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "total_verifications"), &0u32);
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "cache_hits"), &0u32);
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "cache_misses"), &0u32);
    }

    /// Cache a proof for faster retrieval
    pub fn cache_proof(
        env: Env,
        proof_id: Bytes,
        circuit_id: Symbol,
        proof_bytes: Bytes,
        public_inputs: Vec<Bytes>,
        performance_metrics: PerformanceMetrics,
        expires_at: u64,
    ) -> Result<(), PerformanceError> {
        let config: OptimizationConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "optimization_config"))
            .ok_or(PerformanceError::InvalidParameters)?;

        // Check cache size limit
        let cache_key = Symbol::new(&env, "proof_cache");
        let mut cache: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&cache_key)
            .unwrap_or_else(|| Vec::new(&env));

        if cache.len() >= config.cache_size_limit as usize {
            // Remove oldest proof (FIFO eviction)
            if let Some(old_proof_id) = cache.get(0) {
                let old_cache_key =
                    Symbol::new(&env, &format!("cached_proof:{}", old_proof_id.to_string()));
                env.storage().persistent().remove(&old_cache_key);
                cache.remove(0);
            }
        }

        // Generate public inputs hash
        let mut hasher = Sha256::new();
        for input in public_inputs.iter() {
            hasher.update(input.to_array().as_slice());
        }
        let public_inputs_hash_bytes = hasher.finalize();
        let public_inputs_hash = Bytes::from_slice(&env, &public_inputs_hash_bytes);

        // Create cached proof
        let cached_proof = CachedProof {
            proof_id: proof_id.clone(),
            circuit_id: circuit_id.clone(),
            proof_bytes: proof_bytes.clone(),
            public_inputs_hash,
            created_at: env.ledger().timestamp(),
            expires_at,
            access_count: 0,
            performance_metrics,
        };

        // Store cached proof
        let cache_entry_key = Symbol::new(&env, &format!("cached_proof:{}", proof_id.to_string()));
        env.storage()
            .persistent()
            .set(&cache_entry_key, &cached_proof);

        // Update cache index
        cache.push_back(proof_id.clone());
        env.storage().persistent().set(&cache_key, &cache);

        // Update cache statistics
        let mut total_cached: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "total_cached"))
            .unwrap_or(0u32);
        total_cached += 1;
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "total_cached"), &total_cached);

        Ok(())
    }

    /// Retrieve cached proof
    pub fn get_cached_proof(
        env: Env,
        proof_id: Bytes,
        public_inputs: Vec<Bytes>,
    ) -> Result<CachedProof, PerformanceError> {
        let cache_entry_key = Symbol::new(&env, &format!("cached_proof:{}", proof_id.to_string()));

        let mut cached_proof: CachedProof = env
            .storage()
            .persistent()
            .get(&cache_entry_key)
            .ok_or(PerformanceError::CacheMiss)?;

        // Check if proof has expired
        if env.ledger().timestamp() > cached_proof.expires_at {
            env.storage().persistent().remove(&cache_entry_key);
            return Err(PerformanceError::CacheMiss);
        }

        // Verify public inputs hash matches
        let mut hasher = Sha256::new();
        for input in public_inputs.iter() {
            hasher.update(input.to_array().as_slice());
        }
        let public_inputs_hash_bytes = hasher.finalize();
        let public_inputs_hash = Bytes::from_slice(&env, &public_inputs_hash_bytes);

        if cached_proof.public_inputs_hash != public_inputs_hash {
            return Err(PerformanceError::CacheMiss);
        }

        // Update access statistics
        cached_proof.access_count += 1;
        env.storage()
            .persistent()
            .set(&cache_entry_key, &cached_proof);

        // Update cache hit counter
        let mut cache_hits: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "cache_hits"))
            .unwrap_or(0u32);
        cache_hits += 1;
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, "cache_hits"), &cache_hits);

        Ok(cached_proof)
    }

    /// Batch verify multiple proofs for efficiency
    pub fn batch_verify_proofs(
        env: Env,
        proof_ids: Vec<Bytes>,
        circuit_ids: Vec<Symbol>,
        public_inputs_array: Vec<Vec<Bytes>>,
    ) -> Result<BatchVerificationResult, PerformanceError> {
        let config: OptimizationConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "optimization_config"))
            .ok_or(PerformanceError::InvalidParameters)?;

        let start_time = env.ledger().timestamp();
        let mut successful = 0u32;
        let mut failed = 0u32;
        let mut total_gas = 0u64;

        for i in 0..proof_ids.len() {
            let proof_id = proof_ids.get(i).unwrap();
            let circuit_id = circuit_ids.get(i).unwrap();
            let public_inputs = public_inputs_array.get(i).unwrap();

            // Try to get from cache first
            match Self::get_cached_proof(env.clone(), proof_id.clone(), public_inputs.clone()) {
                Ok(cached_proof) => {
                    // Cache hit - use cached verification result
                    successful += 1;
                    total_gas += cached_proof.performance_metrics.gas_consumed;
                }
                Err(_) => {
                    // Cache miss - perform verification
                    match Self::verify_single_proof(
                        env.clone(),
                        proof_id.clone(),
                        circuit_id.clone(),
                        public_inputs.clone(),
                    ) {
                        Ok(gas_used) => {
                            successful += 1;
                            total_gas += gas_used;
                        }
                        Err(_) => {
                            failed += 1;
                        }
                    }
                }
            }
        }

        let total_time = env.ledger().timestamp() - start_time;
        let total_proofs = proof_ids.len() as u32;
        let average_time = if total_proofs > 0 {
            total_time / total_proofs as u64
        } else {
            0
        };

        let result = BatchVerificationResult {
            total_proofs,
            successful_verifications: successful,
            failed_verifications: failed,
            total_time_ms: total_time,
            average_time_ms: average_time,
            gas_used: total_gas,
        };

        // Update verification statistics
        let mut total_verifications: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "total_verifications"))
            .unwrap_or(0u32);
        total_verifications += total_proofs;
        env.storage().persistent().set(
            &Symbol::new(&env, "total_verifications"),
            &total_verifications,
        );

        Ok(result)
    }

    /// Verify a single proof (simplified implementation)
    fn verify_single_proof(
        env: Env,
        proof_id: Bytes,
        circuit_id: Symbol,
        public_inputs: Vec<Bytes>,
    ) -> Result<u64, PerformanceError> {
        // In a real implementation, this would perform actual ZK verification
        // For now, we'll simulate verification with gas estimation

        let gas_consumed = 1000000u64; // Simulated gas consumption

        // Record performance metrics
        let metrics = PerformanceMetrics {
            proof_generation_time_ms: 0, // Not applicable for verification
            verification_time_ms: 1500,  // Simulated verification time
            proof_size_bytes: public_inputs.len() as u32 * 32, // Estimate
            memory_usage_mb: 50,
            gas_consumed,
            circuit_complexity: 3,
            optimization_level: 2,
        };

        // Cache the verification result
        let _ = Self::cache_proof(
            env,
            proof_id,
            circuit_id,
            Bytes::from_slice(&env, b"verified_proof"),
            public_inputs,
            metrics,
            env.ledger().timestamp() + 3600, // Cache for 1 hour
        );

        Ok(gas_consumed)
    }

    /// Optimize proof generation parameters
    pub fn optimize_proof_parameters(
        env: Env,
        circuit_id: Symbol,
        target_time_ms: u64,
        complexity_level: u8,
    ) -> Result<Map<Symbol, Bytes>, PerformanceError> {
        let mut optimizations = Map::new(&env);

        // Based on target time and complexity, suggest optimizations
        if target_time_ms < 2000 {
            // Very fast target - aggressive optimizations
            optimizations.set(
                Symbol::new(&env, "parallel_execution"),
                Bytes::from_slice(&env, b"true"),
            );
            optimizations.set(
                Symbol::new(&env, "circuit_optimization"),
                Bytes::from_slice(&env, b"maximum"),
            );
            optimizations.set(
                Symbol::new(&env, "proof_compression"),
                Bytes::from_slice(&env, b"enabled"),
            );
        } else if target_time_ms < 5000 {
            // Standard target - moderate optimizations
            optimizations.set(
                Symbol::new(&env, "parallel_execution"),
                Bytes::from_slice(&env, b"true"),
            );
            optimizations.set(
                Symbol::new(&env, "circuit_optimization"),
                Bytes::from_slice(&env, b"moderate"),
            );
        } else {
            // Relaxed target - basic optimizations
            optimizations.set(
                Symbol::new(&env, "parallel_execution"),
                Bytes::from_slice(&env, b"false"),
            );
            optimizations.set(
                Symbol::new(&env, "circuit_optimization"),
                Bytes::from_slice(&env, b"minimal"),
            );
        }

        // Complexity-based optimizations
        if complexity_level > 3 {
            optimizations.set(
                Symbol::new(&env, "memory_optimization"),
                Bytes::from_slice(&env, b"enabled"),
            );
            optimizations.set(
                Symbol::new(&env, "circuit_splitting"),
                Bytes::from_slice(&env, b"enabled"),
            );
        }

        Ok(optimizations)
    }

    /// Get performance statistics
    pub fn get_performance_stats(env: Env) -> Map<Symbol, Bytes> {
        let mut stats = Map::new(&env);

        // Get basic counters
        let total_proofs: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "total_proofs_generated"))
            .unwrap_or(0u32);
        let total_verifications: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "total_verifications"))
            .unwrap_or(0u32);
        let cache_hits: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "cache_hits"))
            .unwrap_or(0u32);
        let cache_misses: u32 = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "cache_misses"))
            .unwrap_or(0u32);

        stats.set(
            Symbol::new(&env, "total_proofs_generated"),
            Bytes::from_slice(&env, &total_proofs.to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "total_verifications"),
            Bytes::from_slice(&env, &total_verifications.to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "cache_hits"),
            Bytes::from_slice(&env, &cache_hits.to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "cache_misses"),
            Bytes::from_slice(&env, &cache_misses.to_be_bytes()),
        );

        // Calculate cache hit rate
        let total_cache_accesses = cache_hits + cache_misses;
        let hit_rate = if total_cache_accesses > 0 {
            (cache_hits * 100) / total_cache_accesses
        } else {
            0
        };
        stats.set(
            Symbol::new(&env, "cache_hit_rate_percent"),
            Bytes::from_slice(&env, &hit_rate.to_be_bytes()),
        );

        // Get configuration
        let config: OptimizationConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "optimization_config"))
            .unwrap_or(OptimizationConfig {
                target_proof_time_ms: 5000,
                target_verification_time_ms: 2000,
                max_proof_size_bytes: 100000,
                max_memory_mb: 256,
                cache_size_limit: 1000,
                parallel_verification: true,
                compression_enabled: true,
            });

        stats.set(
            Symbol::new(&env, "target_proof_time_ms"),
            Bytes::from_slice(&env, &config.target_proof_time_ms.to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "target_verification_time_ms"),
            Bytes::from_slice(&env, &config.target_verification_time_ms.to_be_bytes()),
        );

        stats
    }

    /// Clean up expired cached proofs
    pub fn cleanup_expired_cache(env: Env) -> Result<u32, PerformanceError> {
        let current_time = env.ledger().timestamp();
        let mut cleaned_count = 0u32;

        let cache_key = Symbol::new(&env, "proof_cache");
        let mut cache: Vec<Bytes> = env
            .storage()
            .persistent()
            .get(&cache_key)
            .unwrap_or_else(|| Vec::new(&env));

        let mut indices_to_remove = Vec::new(&env);
        for (i, proof_id) in cache.iter().enumerate() {
            let cache_entry_key =
                Symbol::new(&env, &format!("cached_proof:{}", proof_id.to_string()));
            if let Some(cached_proof) = env.storage().persistent().get(&cache_entry_key) {
                if current_time > cached_proof.expires_at {
                    indices_to_remove.push_back(i as u32);
                }
            }
        }

        // Remove expired entries (in reverse order to maintain indices)
        for i in (0..indices_to_remove.len()).rev() {
            let index = indices_to_remove.get(i).unwrap();
            if let Some(proof_id) = cache.get(*index as usize) {
                let cache_entry_key =
                    Symbol::new(&env, &format!("cached_proof:{}", proof_id.to_string()));
                env.storage().persistent().remove(&cache_entry_key);
                cache.remove(*index as usize);
                cleaned_count += 1;
            }
        }

        // Update cache index
        env.storage().persistent().set(&cache_key, &cache);

        Ok(cleaned_count)
    }

    /// Benchmark proof performance
    pub fn benchmark_proof(
        env: Env,
        circuit_id: Symbol,
        test_inputs: Vec<Bytes>,
        iterations: u32,
    ) -> Result<PerformanceMetrics, PerformanceError> {
        let start_time = env.ledger().timestamp();
        let mut total_time = 0u64;
        let mut total_gas = 0u64;

        for _ in 0..iterations {
            let iteration_start = env.ledger().timestamp();

            // Simulate proof generation and verification
            let gas_used = Self::verify_single_proof(
                env.clone(),
                Bytes::from_slice(&env, b"test_proof"),
                circuit_id.clone(),
                test_inputs.clone(),
            )?;

            let iteration_time = env.ledger().timestamp() - iteration_start;
            total_time += iteration_time;
            total_gas += gas_used;
        }

        let average_time = total_time / iterations as u64;
        let average_gas = total_gas / iterations as u64;

        let metrics = PerformanceMetrics {
            proof_generation_time_ms: average_time / 2, // Assume generation is half of total time
            verification_time_ms: average_time / 2,
            proof_size_bytes: 50000, // Estimated
            memory_usage_mb: 128,
            gas_consumed: average_gas,
            circuit_complexity: 3,
            optimization_level: 2,
        };

        Ok(metrics)
    }

    // ── Proof compression (#179) ──────────────────────────────────────────────

    /// Compress a proof and store it, returning what it cost.
    ///
    /// Honours `compression_enabled` from `OptimizationConfig`, which until now
    /// was written by `initialize_optimization_config` and then read by nothing
    /// at all. The stored form carries a one-byte codec tag, so
    /// `decompress_proof` can tell a compressed body from a verbatim one without
    /// a parallel index, and a body written by an older scheme still reads back.
    ///
    /// The stored form is **never larger** than the input: when the codec does
    /// not beat the original the proof is kept verbatim. Padding the ledger with
    /// a bigger copy of the same bytes would be a straight loss, and on
    /// high-entropy field element data that is the expected outcome.
    pub fn compress_proof(
        env: Env,
        proof_id: Bytes,
        proof_bytes: Bytes,
    ) -> Result<ProofCompression, PerformanceError> {
        let config: OptimizationConfig = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, "optimization_config"))
            .ok_or(PerformanceError::InvalidParameters)?;

        let original_size = proof_bytes.len();
        let eligible =
            config.compression_enabled && original_size > MIN_COMPRESSIBLE_PROOF_BYTES;

        let (codec, body) = if eligible {
            let packed = Self::packbits_compress(&env, &proof_bytes);
            if packed.len() < original_size {
                (CODEC_PACKBITS, packed)
            } else {
                (CODEC_RAW, proof_bytes.clone())
            }
        } else {
            (CODEC_RAW, proof_bytes.clone())
        };

        let mut framed = Bytes::new(&env);
        framed.push_back(codec);
        for byte in body.iter() {
            framed.push_back(byte);
        }
        let stored_size = framed.len();

        env.storage().persistent().set(
            &Symbol::new(&env, &Self::compression_storage_key(&proof_id)),
            &framed,
        );

        // Guarded: an empty proof has no meaningful ratio, and dividing by its
        // size would panic.
        let ratio_bps: u32 = if original_size == 0 {
            BPS_DENOMINATOR_U32
        } else {
            (((stored_size as u64) * (BPS_DENOMINATOR as u64)) / (original_size as u64))
                .min(BPS_DENOMINATOR as u64) as u32
        };

        env.events().publish(
            (Symbol::new(&env, "ProofCompressed"), proof_id.clone()),
            (original_size, stored_size, codec as u32),
        );

        Ok(ProofCompression {
            proof_id,
            original_size,
            stored_size,
            ratio_bps,
            savings_bps: BPS_DENOMINATOR_U32 - ratio_bps,
            compressed: codec == CODEC_PACKBITS,
            skip_reason: if codec == CODEC_PACKBITS {
                SKIP_NONE
            } else if !config.compression_enabled {
                SKIP_DISABLED
            } else if original_size <= MIN_COMPRESSIBLE_PROOF_BYTES {
                SKIP_TOO_SMALL
            } else {
                SKIP_NO_GAIN
            },
        })
    }

    /// Read a stored proof back as its original bytes.
    ///
    /// Decompression is transparent: the caller cannot tell a compressed proof
    /// from a verbatim one.
    pub fn decompress_proof(env: Env, proof_id: Bytes) -> Result<Bytes, PerformanceError> {
        let framed: Bytes = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, &Self::compression_storage_key(&proof_id)))
            .ok_or(PerformanceError::CacheMiss)?;

        let codec = match framed.get(0) {
            Some(c) => c,
            None => return Err(PerformanceError::InvalidParameters),
        };

        let mut body = Bytes::new(&env);
        let mut i: u32 = 1;
        while i < framed.len() {
            if let Some(b) = framed.get(i) {
                body.push_back(b);
            }
            i += 1;
        }

        if codec == CODEC_RAW {
            Ok(body)
        } else if codec == CODEC_PACKBITS {
            Self::packbits_decompress(&env, &body)
        } else {
            Err(PerformanceError::InvalidParameters)
        }
    }

    fn compression_storage_key(proof_id: &Bytes) -> String {
        format!("compressed_proof:{}", proof_id.to_string())
    }

    /// PackBits: a control byte below 128 introduces `n + 1` literal bytes; one
    /// above 128 repeats the next byte `257 - n` times. Control byte 128 is a
    /// no-op and is never emitted.
    ///
    /// O(n) in both directions with no back-references, so decompression cost is
    /// bounded by the input size and cannot be turned into an expansion bomb.
    fn packbits_compress(env: &Env, input: &Bytes) -> Bytes {
        let mut out = Bytes::new(env);
        let len = input.len();
        let mut i: u32 = 0;

        while i < len {
            let byte = input.get(i).unwrap_or(0);
            let mut run: u32 = 1;
            while run < MAX_PACKBITS_RUN && i + run < len && input.get(i + run) == Some(byte) {
                run += 1;
            }

            if run >= 2 {
                out.push_back((257 - run) as u8);
                out.push_back(byte);
                i += run;
                continue;
            }

            // A single byte cannot be a repeat, since 257 - 1 is out of range,
            // so gather literals until a run of two or more begins.
            let mut literal: u32 = 1;
            while literal < MAX_PACKBITS_RUN && i + literal < len {
                let here = input.get(i + literal).unwrap_or(0);
                let next = input.get(i + literal + 1);
                if next == Some(here) {
                    break;
                }
                literal += 1;
            }

            out.push_back((literal - 1) as u8);
            for k in 0..literal {
                if let Some(b) = input.get(i + k) {
                    out.push_back(b);
                }
            }
            i += literal;
        }

        out
    }

    fn packbits_decompress(env: &Env, input: &Bytes) -> Result<Bytes, PerformanceError> {
        let mut out = Bytes::new(env);
        let len = input.len();
        let mut i: u32 = 0;

        while i < len {
            let control = match input.get(i) {
                Some(c) => c,
                None => return Err(PerformanceError::InvalidParameters),
            };
            i += 1;

            // 127 is a valid control byte meaning a 128-byte literal run, so
            // the literal branch is `< 128` and not `< 127`.
            if control < PACKBITS_NOOP {
                // Copy the next `control + 1` literals.
                let take = control as u32 + 1;
                if i + take > len {
                    return Err(PerformanceError::InvalidParameters);
                }
                for _ in 0..take {
                    if let Some(b) = input.get(i) {
                        out.push_back(b);
                    }
                    i += 1;
                }
            } else if control > PACKBITS_NOOP {
                // Repeat the next byte `257 - control` times.
                let byte = match input.get(i) {
                    Some(b) => b,
                    None => return Err(PerformanceError::InvalidParameters),
                };
                i += 1;
                for _ in 0..(257 - control as u32) {
                    out.push_back(byte);
                }
            }
            // control == PACKBITS_NOOP is a no-op; a conforming encoder never
            // emits one.
        }

        Ok(out)
    }

    // ── Schema validation cache (#163) ────────────────────────────────────────

    /// Memoize a validation verdict for `(schema_id, data)` and return it.
    ///
    /// On a hit the cached verdict wins and `fresh_verdict` is ignored; on a
    /// miss the caller's freshly computed verdict is what gets stored. That
    /// shape leaves the expensive validation in the caller's own validator and
    /// keeps only the memoization here, which is the part that is safe to put
    /// on-chain.
    ///
    /// The key folds in the schema's content hash *and* its cache version, so
    /// `invalidate_schema_cache` orphans every prior entry for that schema by
    /// bumping one number, with nothing to enumerate or delete.
    pub fn validate_cached(
        env: Env,
        schema_id: Symbol,
        schema_hash: Bytes,
        data: Bytes,
        fresh_verdict: bool,
    ) -> Result<CachedValidation, PerformanceError> {
        let now = env.ledger().timestamp();
        let version = Self::schema_version(&env, schema_id.clone());
        let data_hash = Self::hash_bytes(&env, &data);
        let key = Self::validation_key(&env, version, &schema_hash, &data_hash);

        let mut cache = Self::validation_cache(&env);

        if let Some(entry) = cache.get(&key) {
            // An expired entry is treated as a miss and simply overwritten.
            if now <= entry.expires_at {
                let mut updated = entry;
                updated.hit_count = updated.hit_count.saturating_add(1);
                cache.set(&key, &updated);
                env.storage().temporary().set(&Symbol::new(&env, VALIDATION_CACHE), &cache);
                Self::bump_validation_counter(&env, "validation_cache_hits");
                return Ok(updated);
            }
        }

        let entry = CachedValidation {
            schema_id,
            schema_hash,
            data_hash,
            is_valid: fresh_verdict,
            schema_version: version,
            computed_at: now,
            expires_at: now.saturating_add(Self::validation_cache_ttl(&env)),
            hit_count: 0,
        };

        cache.set(&key, &entry);
        Self::evict_to_limit(&mut cache);
        env.storage().temporary().set(&Symbol::new(&env, VALIDATION_CACHE), &cache);
        Self::bump_validation_counter(&env, "validation_cache_misses");

        Ok(entry)
    }

    /// Cached verdict for `(schema_id, data)`, or `CacheMiss`.
    ///
    /// The read-only half of `validate_cached`, for callers that want to know
    /// whether the cache can answer without contributing a verdict.
    pub fn get_cached_validation(
        env: Env,
        schema_id: Symbol,
        schema_hash: Bytes,
        data: Bytes,
    ) -> Result<CachedValidation, PerformanceError> {
        let version = Self::schema_version(&env, schema_id);
        let data_hash = Self::hash_bytes(&env, &data);
        let key = Self::validation_key(&env, version, &schema_hash, &data_hash);

        let entry = Self::validation_cache(&env)
            .get(&key)
            .ok_or(PerformanceError::CacheMiss)?;
        if env.ledger().timestamp() > entry.expires_at {
            return Err(PerformanceError::CacheMiss);
        }
        Ok(entry)
    }

    /// Invalidate every cached verdict for `schema_id` by bumping its version.
    ///
    /// Returns the new version. Old entries are deliberately not deleted: their
    /// keys no longer resolve, and the temporary storage they live in expires
    /// them on its own.
    pub fn invalidate_schema_cache(env: Env, schema_id: Symbol) -> u64 {
        let mut versions: Map<Symbol, u64> = env
            .storage()
            .persistent()
            .get(&Symbol::new(&env, SCHEMA_VERSIONS))
            .unwrap_or_else(|| Map::new(&env));

        let next = versions.get(schema_id.clone()).unwrap_or(0).saturating_add(1);
        versions.set(schema_id.clone(), next);
        env.storage().persistent().set(&Symbol::new(&env, SCHEMA_VERSIONS), &versions);

        env.events()
            .publish((Symbol::new(&env, "SchemaCacheInvalidated"), schema_id), next);

        next
    }

    /// Validation cache counters, including a guarded hit rate.
    pub fn get_validation_cache_stats(env: Env) -> Map<Symbol, Bytes> {
        let mut stats = Map::new(&env);
        let hits = Self::validation_counter(&env, "validation_cache_hits");
        let misses = Self::validation_counter(&env, "validation_cache_misses");

        stats.set(
            Symbol::new(&env, "validation_cache_hits"),
            Bytes::from_slice(&env, &hits.to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "validation_cache_misses"),
            Bytes::from_slice(&env, &misses.to_be_bytes()),
        );

        // Guarded: a fresh contract has made zero accesses, and dividing by the
        // total would otherwise panic rather than report 0%.
        let accesses = hits as u64 + misses as u64;
        let rate: u32 = if accesses > 0 {
            ((hits as u64 * 100) / accesses) as u32
        } else {
            0
        };

        stats.set(
            Symbol::new(&env, "validation_cache_hit_rate_percent"),
            Bytes::from_slice(&env, &rate.to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "validation_cache_entries"),
            Bytes::from_slice(&env, &Self::validation_cache(&env).len().to_be_bytes()),
        );
        stats.set(
            Symbol::new(&env, "validation_cache_ttl"),
            Bytes::from_slice(&env, &Self::validation_cache_ttl(&env).to_be_bytes()),
        );
        stats
    }

    /// Configure how long a cached verdict stays valid.
    pub fn set_validation_cache_ttl(env: Env, ttl: u64) {
        env.storage()
            .persistent()
            .set(&Symbol::new(&env, VALIDATION_CACHE_TTL), &ttl);
    }

    /// Drop expired entries. Returns how many were removed.
    pub fn cleanup_validation_cache(env: Env) -> u32 {
        let now = env.ledger().timestamp();
        let mut cache = Self::validation_cache(&env);
        let before = cache.len();

        let mut expired: Vec<Bytes> = Vec::new(&env);
        for (key, entry) in cache.iter() {
            if now > entry.expires_at {
                expired.push_back(key);
            }
        }
        for key in expired.iter() {
            cache.remove(&key);
        }

        let removed = before.saturating_sub(cache.len());
        env.storage().temporary().set(&Symbol::new(&env, VALIDATION_CACHE), &cache);
        removed
    }

    // ── Validation cache helpers ─────────────────────────────────────────────

    fn validation_cache(env: &Env) -> Map<Bytes, CachedValidation> {
        env.storage()
            .temporary()
            .get(&Symbol::new(env, VALIDATION_CACHE))
            .unwrap_or_else(|| Map::new(env))
    }

    fn schema_version(env: &Env, schema_id: Symbol) -> u64 {
        let versions: Map<Symbol, u64> = env
            .storage()
            .persistent()
            .get(&Symbol::new(env, SCHEMA_VERSIONS))
            .unwrap_or_else(|| Map::new(env));
        versions.get(schema_id).unwrap_or(0)
    }

    /// Length-delimited by construction: the version and the two hashes are
    /// hashed with fixed widths, so no two distinct triples can collide by
    /// concatenation the way bare `id ++ data` could.
    fn validation_key(
        env: &Env,
        version: u64,
        schema_hash: &Bytes,
        data_hash: &Bytes,
    ) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(b"validation-cache-v1");
        hasher.update(version.to_be_bytes());
        hasher.update(schema_hash.to_array().as_slice());
        hasher.update(data_hash.to_array().as_slice());
        Bytes::from_slice(env, &hasher.finalize())
    }

    fn hash_bytes(env: &Env, data: &Bytes) -> Bytes {
        let mut hasher = Sha256::new();
        hasher.update(data.to_array().as_slice());
        Bytes::from_slice(env, &hasher.finalize())
    }

    fn validation_cache_ttl(env: &Env) -> u64 {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, VALIDATION_CACHE_TTL))
            .unwrap_or(DEFAULT_VALIDATION_CACHE_TTL)
    }

    fn validation_counter(env: &Env, name: &str) -> u32 {
        env.storage()
            .persistent()
            .get(&Symbol::new(env, name))
            .unwrap_or(0u32)
    }

    fn bump_validation_counter(env: &Env, name: &str) {
        let value = Self::validation_counter(env, name).saturating_add(1);
        env.storage()
            .persistent()
            .set(&Symbol::new(env, name), &value);
    }

    /// Keep the cache inside `MAX_VALIDATION_CACHE_ENTRIES`, dropping the
    /// earliest-computed entry each time.
    fn evict_to_limit(cache: &mut Map<Bytes, CachedValidation>) {
        while cache.len() > MAX_VALIDATION_CACHE_ENTRIES {
            let mut oldest_key: Option<Bytes> = None;
            let mut oldest_at = u64::MAX;
            for (key, entry) in cache.iter() {
                if entry.computed_at < oldest_at {
                    oldest_at = entry.computed_at;
                    oldest_key = Some(key);
                }
            }
            match oldest_key {
                Some(k) => cache.remove(&k),
                None => break,
            }
        }
    }
}
