use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    Address, Bytes, Env, Map, Symbol, Vec,
};

use crate::{clamp_page_size, PaginatedAddresses};

// ── Constants ─────────────────────────────────────────────────────────────────

const GEO_TTL_LEDGERS: u32 = 6_307_200;
const MAX_JURISDICTIONS: u32 = 100;
const MAX_TRAVEL_ENTRIES: u32 = 50;
const MAX_REGIONS: u32 = 20;
const MAX_RULES_PER_JURISDICTION: u32 = 10;

// ── Storage keys ──────────────────────────────────────────────────────────────

const KEY_ADMIN: &str = "admin";

// ── Errors ────────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum GeographicError {
    Unauthorized = 1,
    NotFound = 2,
    InvalidInput = 3,
    NotInitialized = 4,
    AlreadyInitialized = 5,
    AlreadyExists = 6,
    JurisdictionBlocked = 7,
    TravelNotAuthorized = 8,
    MaxJurisdictionsReached = 9,
    MaxTravelEntriesReached = 10,
    InsufficientGeoVerification = 11,
    ExpiredGeoTag = 12,
    RegionNotSupported = 13,
    CrossBorderRestriction = 14,
}

// ── Storage key enum ──────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
enum GeoKey {
    Config,
    Jurisdiction(Bytes),
    JurisdictionIndex,
    Rule(Bytes, Bytes),
    GeoTag(Bytes),
    TravelLog(Address, u64),
    TravelLogIndex(Address),
    CrossBorderPolicy(Bytes),
    RestrictedRegion(Bytes),
}

// ── Data structures ───────────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoConfig {
    pub enabled: bool,
    pub default_verification_required: bool,
    pub travel_notification_required: bool,
    pub max_travel_duration_secs: u64,
    pub geo_staleness_secs: u64,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestrictionLevel {
    Allowed,
    Restricted,
    Blocked,
    RequiresApproval,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Jurisdiction {
    pub code: Bytes,
    pub name: Bytes,
    pub region: Bytes,
    pub restriction_level: RestrictionLevel,
    pub regulatory_body: Bytes,
    pub active: bool,
    pub created: u64,
    pub updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoRestrictionRule {
    pub jurisdiction: Bytes,
    pub target_jurisdiction: Bytes,
    pub restriction: RestrictionLevel,
    pub credential_type: Bytes,
    pub requires_travel_auth: bool,
    pub max_stay_days: u32,
    pub active: bool,
    pub created: u64,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoTag {
    pub credential_id: Bytes,
    pub issuing_jurisdiction: Bytes,
    pub holder_jurisdiction: Bytes,
    pub issued_at: u64,
    pub expires_at: u64,
    pub verification_level: u32,
    pub metadata: Map<Symbol, Bytes>,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TravelAuthorization {
    pub holder: Address,
    pub from_jurisdiction: Bytes,
    pub to_jurisdiction: Bytes,
    pub authorized_at: u64,
    pub expires_at: u64,
    pub purpose: Bytes,
    pub approved: bool,
    pub approved_by: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossBorderPolicy {
    pub from_jurisdiction: Bytes,
    pub to_jurisdiction: Bytes,
    pub policy: RestrictionLevel,
    pub requires_visa: bool,
    pub max_credentials: u32,
    pub notify_regulator: bool,
    pub active: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeoVerificationResult {
    pub credential_id: Bytes,
    pub credential_type: Bytes,
    pub issuing_jurisdiction: Bytes,
    pub holder_jurisdiction: Bytes,
    pub usage_jurisdiction: Bytes,
    pub allowed: bool,
    pub restriction_level: RestrictionLevel,
    pub reason: Bytes,
    pub timestamp: u64,
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[contract]
pub struct GeographicRestriction;

#[contractimpl]
impl GeographicRestriction {
    // ── Initialization ────────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) -> Result<(), GeographicError> {
        if env.storage().instance().has(&Symbol::new(&env, KEY_ADMIN)) {
            return Err(GeographicError::AlreadyInitialized);
        }

        env.storage().instance().set(&Symbol::new(&env, KEY_ADMIN), &admin);

        let config = GeoConfig {
            enabled: true,
            default_verification_required: true,
            travel_notification_required: true,
            max_travel_duration_secs: 90 * 24 * 60 * 60,
            geo_staleness_secs: 30 * 24 * 60 * 60,
            last_updated: env.ledger().timestamp(),
        };
        Self::persist(&env, &GeoKey::Config, &config);

        Ok(())
    }

    // ── Configuration ─────────────────────────────────────────────────────────

    pub fn update_config(
        env: Env,
        caller: Address,
        enabled: Option<bool>,
        default_verification_required: Option<bool>,
        travel_notification_required: Option<bool>,
        max_travel_duration_secs: Option<u64>,
        geo_staleness_secs: Option<u64>,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        let mut config: GeoConfig = env.storage().persistent()
            .get(&GeoKey::Config)
            .ok_or(GeographicError::NotInitialized)?;

        if let Some(v) = enabled { config.enabled = v; }
        if let Some(v) = default_verification_required { config.default_verification_required = v; }
        if let Some(v) = travel_notification_required { config.travel_notification_required = v; }
        if let Some(v) = max_travel_duration_secs { config.max_travel_duration_secs = v; }
        if let Some(v) = geo_staleness_secs { config.geo_staleness_secs = v; }
        config.last_updated = env.ledger().timestamp();

        Self::persist(&env, &GeoKey::Config, &config);
        Ok(())
    }

    pub fn get_config(env: Env) -> GeoConfig {
        env.storage().persistent()
            .get(&GeoKey::Config)
            .unwrap_or(GeoConfig {
                enabled: true,
                default_verification_required: true,
                travel_notification_required: true,
                max_travel_duration_secs: 90 * 24 * 60 * 60,
                geo_staleness_secs: 30 * 24 * 60 * 60,
                last_updated: 0,
            })
    }

    // ── Jurisdiction management ───────────────────────────────────────────────

    pub fn register_jurisdiction(
        env: Env,
        caller: Address,
        code: Bytes,
        name: Bytes,
        region: Bytes,
        restriction_level: RestrictionLevel,
        regulatory_body: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        if code.is_empty() || name.is_empty() {
            return Err(GeographicError::InvalidInput);
        }

        let jk = GeoKey::Jurisdiction(code.clone());
        if env.storage().persistent().has(&jk) {
            return Err(GeographicError::AlreadyExists);
        }

        let mut idx: Vec<Bytes> = env.storage().persistent()
            .get(&GeoKey::JurisdictionIndex)
            .unwrap_or_else(|| Vec::new(&env));
        if idx.len() as u32 >= MAX_JURISDICTIONS {
            return Err(GeographicError::MaxJurisdictionsReached);
        }

        let jurisdiction = Jurisdiction {
            code: code.clone(),
            name,
            region: region.clone(),
            restriction_level,
            regulatory_body,
            active: true,
            created: env.ledger().timestamp(),
            updated: env.ledger().timestamp(),
        };

        Self::persist(&env, &jk, &jurisdiction);
        idx.push_back(code);
        Self::persist(&env, &GeoKey::JurisdictionIndex, &idx);

        env.events().publish(
            (Symbol::new(&env, "jurisdiction_registered"),),
            (jurisdiction.code.clone(), region),
        );
        Ok(())
    }

    pub fn update_jurisdiction(
        env: Env,
        caller: Address,
        code: Bytes,
        restriction_level: RestrictionLevel,
        regulatory_body: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        let jk = GeoKey::Jurisdiction(code.clone());
        let mut jurisdiction: Jurisdiction = env.storage().persistent()
            .get(&jk)
            .ok_or(GeographicError::NotFound)?;

        jurisdiction.restriction_level = restriction_level;
        jurisdiction.regulatory_body = regulatory_body;
        jurisdiction.updated = env.ledger().timestamp();

        Self::persist(&env, &jk, &jurisdiction);
        Ok(())
    }

    pub fn deactivate_jurisdiction(
        env: Env,
        caller: Address,
        code: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        let jk = GeoKey::Jurisdiction(code.clone());
        let mut jurisdiction: Jurisdiction = env.storage().persistent()
            .get(&jk)
            .ok_or(GeographicError::NotFound)?;
        jurisdiction.active = false;
        jurisdiction.updated = env.ledger().timestamp();
        Self::persist(&env, &jk, &jurisdiction);
        Ok(())
    }

    pub fn get_jurisdiction(env: Env, code: Bytes) -> Option<Jurisdiction> {
        env.storage().persistent().get(&GeoKey::Jurisdiction(code))
    }

    pub fn get_all_jurisdictions(env: Env) -> Vec<Bytes> {
        env.storage().persistent()
            .get(&GeoKey::JurisdictionIndex)
            .unwrap_or_else(|| Vec::new(&env))
    }

    // ── Restriction rules ─────────────────────────────────────────────────────

    pub fn register_restriction_rule(
        env: Env,
        caller: Address,
        jurisdiction: Bytes,
        target_jurisdiction: Bytes,
        restriction: RestrictionLevel,
        credential_type: Bytes,
        requires_travel_auth: bool,
        max_stay_days: u32,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        if !env.storage().persistent().has(&GeoKey::Jurisdiction(jurisdiction.clone())) {
            return Err(GeographicError::NotFound);
        }
        if !env.storage().persistent().has(&GeoKey::Jurisdiction(target_jurisdiction.clone())) {
            return Err(GeographicError::NotFound);
        }

        let rk = GeoKey::Rule(jurisdiction.clone(), target_jurisdiction.clone());
        let rule = GeoRestrictionRule {
            jurisdiction: jurisdiction.clone(),
            target_jurisdiction: target_jurisdiction.clone(),
            restriction,
            credential_type: credential_type.clone(),
            requires_travel_auth,
            max_stay_days,
            active: true,
            created: env.ledger().timestamp(),
        };

        Self::persist(&env, &rk, &rule);

        env.events().publish(
            (Symbol::new(&env, "restriction_rule_registered"),),
            (jurisdiction, target_jurisdiction),
        );
        Ok(())
    }

    pub fn deactivate_restriction_rule(
        env: Env,
        caller: Address,
        jurisdiction: Bytes,
        target_jurisdiction: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        let rk = GeoKey::Rule(jurisdiction, target_jurisdiction);
        let mut rule: GeoRestrictionRule = env.storage().persistent()
            .get(&rk)
            .ok_or(GeographicError::NotFound)?;
        rule.active = false;
        Self::persist(&env, &rk, &rule);
        Ok(())
    }

    pub fn get_restriction_rule(
        env: Env,
        jurisdiction: Bytes,
        target_jurisdiction: Bytes,
    ) -> Option<GeoRestrictionRule> {
        env.storage().persistent().get(&GeoKey::Rule(jurisdiction, target_jurisdiction))
    }

    // ── Cross-border policies ─────────────────────────────────────────────────

    pub fn set_cross_border_policy(
        env: Env,
        caller: Address,
        from_jurisdiction: Bytes,
        to_jurisdiction: Bytes,
        policy: RestrictionLevel,
        requires_visa: bool,
        max_credentials: u32,
        notify_regulator: bool,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        let key = GeoKey::CrossBorderPolicy(from_jurisdiction.clone());
        let border_policy = CrossBorderPolicy {
            from_jurisdiction: from_jurisdiction.clone(),
            to_jurisdiction: to_jurisdiction.clone(),
            policy,
            requires_visa,
            max_credentials,
            notify_regulator,
            active: true,
        };
        Self::persist(&env, &key, &border_policy);

        env.events().publish(
            (Symbol::new(&env, "cross_border_policy_set"),),
            (from_jurisdiction, to_jurisdiction),
        );
        Ok(())
    }

    pub fn get_cross_border_policy(env: Env, from_jurisdiction: Bytes) -> Option<CrossBorderPolicy> {
        env.storage().persistent().get(&GeoKey::CrossBorderPolicy(from_jurisdiction))
    }

    // ── Geo-tagging ───────────────────────────────────────────────────────────

    pub fn create_geo_tag(
        env: Env,
        caller: Address,
        credential_id: Bytes,
        issuing_jurisdiction: Bytes,
        holder_jurisdiction: Bytes,
        verification_level: u32,
        metadata: Map<Symbol, Bytes>,
        expires_at: u64,
    ) -> Result<(), GeographicError> {
        caller.require_auth();

        if credential_id.is_empty() {
            return Err(GeographicError::InvalidInput);
        }
        if !env.storage().persistent().has(&GeoKey::Jurisdiction(issuing_jurisdiction.clone())) {
            return Err(GeographicError::NotFound);
        }
        if !env.storage().persistent().has(&GeoKey::Jurisdiction(holder_jurisdiction.clone())) {
            return Err(GeographicError::NotFound);
        }

        let config = Self::get_config(env.clone());
        if expires_at <= env.ledger().timestamp() {
            return Err(GeographicError::ExpiredGeoTag);
        }
        if expires_at > env.ledger().timestamp() + config.max_travel_duration_secs * 4 {
            return Err(GeographicError::InvalidInput);
        }

        let gk = GeoKey::GeoTag(credential_id.clone());
        if env.storage().persistent().has(&gk) {
            return Err(GeographicError::AlreadyExists);
        }

        let tag = GeoTag {
            credential_id: credential_id.clone(),
            issuing_jurisdiction,
            holder_jurisdiction,
            issued_at: env.ledger().timestamp(),
            expires_at,
            verification_level,
            metadata,
            active: true,
        };

        Self::persist(&env, &gk, &tag);

        env.events().publish(
            (Symbol::new(&env, "geo_tag_created"),),
            credential_id,
        );
        Ok(())
    }

    pub fn get_geo_tag(env: Env, credential_id: Bytes) -> Option<GeoTag> {
        env.storage().persistent().get(&GeoKey::GeoTag(credential_id))
    }

    pub fn deactivate_geo_tag(
        env: Env,
        caller: Address,
        credential_id: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }

        let gk = GeoKey::GeoTag(credential_id.clone());
        let mut tag: GeoTag = env.storage().persistent()
            .get(&gk)
            .ok_or(GeographicError::NotFound)?;
        tag.active = false;
        Self::persist(&env, &gk, &tag);
        Ok(())
    }

    // ── Geographic verification ───────────────────────────────────────────────

    pub fn verify_geographic_usage(
        env: Env,
        credential_id: Bytes,
        credential_type: Bytes,
        usage_jurisdiction: Bytes,
    ) -> Result<GeoVerificationResult, GeographicError> {
        let config = Self::get_config(env.clone());
        if !config.enabled {
            return Ok(GeoVerificationResult {
                credential_id: credential_id.clone(),
                credential_type: credential_type.clone(),
                issuing_jurisdiction: Bytes::new(&env),
                holder_jurisdiction: Bytes::new(&env),
                usage_jurisdiction: usage_jurisdiction.clone(),
                allowed: true,
                restriction_level: RestrictionLevel::Allowed,
                reason: Bytes::from_slice(&env, b"geo_restriction_disabled"),
                timestamp: env.ledger().timestamp(),
            });
        }

        let tag: GeoTag = env.storage().persistent()
            .get(&GeoKey::GeoTag(credential_id.clone()))
            .ok_or(GeographicError::NotFound)?;

        if !tag.active {
            return Err(GeographicError::NotFound);
        }
        if env.ledger().timestamp() > tag.expires_at {
            return Err(GeographicError::ExpiredGeoTag);
        }

        let usage_jur: Option<Jurisdiction> = env.storage().persistent()
            .get(&GeoKey::Jurisdiction(usage_jurisdiction.clone()));

        let issuing_jur: Option<Jurisdiction> = env.storage().persistent()
            .get(&GeoKey::Jurisdiction(tag.issuing_jurisdiction.clone()));

        let holder_jur: Option<Jurisdiction> = env.storage().persistent()
            .get(&GeoKey::Jurisdiction(tag.holder_jurisdiction.clone()));

        if let Some(ref uj) = usage_jur {
            if uj.restriction_level == RestrictionLevel::Blocked {
                return Err(GeographicError::JurisdictionBlocked);
            }
        }

        if tag.issuing_jurisdiction != usage_jurisdiction {
            let rk = GeoKey::Rule(tag.issuing_jurisdiction.clone(), usage_jurisdiction.clone());
            if let Some(rule) = env.storage().persistent().get::<GeoKey, GeoRestrictionRule>(&rk) {
                if !rule.active {
                    return Ok(Self::allowed_result(&env, &credential_id, &credential_type, &tag, &usage_jurisdiction));
                }
                match rule.restriction {
                    RestrictionLevel::Blocked => {
                        return Err(GeographicError::CrossBorderRestriction);
                    }
                    RestrictionLevel::Restricted => {
                        return Ok(GeoVerificationResult {
                            credential_id,
                            credential_type,
                            issuing_jurisdiction: tag.issuing_jurisdiction,
                            holder_jurisdiction: tag.holder_jurisdiction,
                            usage_jurisdiction,
                            allowed: false,
                            restriction_level: RestrictionLevel::Restricted,
                            reason: Bytes::from_slice(&env, b"cross_border_restriction"),
                            timestamp: env.ledger().timestamp(),
                        });
                    }
                    RestrictionLevel::RequiresApproval => {
                        return Ok(GeoVerificationResult {
                            credential_id,
                            credential_type,
                            issuing_jurisdiction: tag.issuing_jurisdiction,
                            holder_jurisdiction: tag.holder_jurisdiction,
                            usage_jurisdiction,
                            allowed: false,
                            restriction_level: RestrictionLevel::RequiresApproval,
                            reason: Bytes::from_slice(&env, b"travel_authorization_required"),
                            timestamp: env.ledger().timestamp(),
                        });
                    }
                    RestrictionLevel::Allowed => {}
                }
            }
        }

        Ok(Self::allowed_result(&env, &credential_id, &credential_type, &tag, &usage_jurisdiction))
    }

    fn allowed_result(
        env: &Env,
        credential_id: &Bytes,
        credential_type: &Bytes,
        tag: &GeoTag,
        usage_jurisdiction: &Bytes,
    ) -> GeoVerificationResult {
        GeoVerificationResult {
            credential_id: credential_id.clone(),
            credential_type: credential_type.clone(),
            issuing_jurisdiction: tag.issuing_jurisdiction.clone(),
            holder_jurisdiction: tag.holder_jurisdiction.clone(),
            usage_jurisdiction: usage_jurisdiction.clone(),
            allowed: true,
            restriction_level: RestrictionLevel::Allowed,
            reason: Bytes::from_slice(env, b"geo_verification_passed"),
            timestamp: env.ledger().timestamp(),
        }
    }

    // ── Travel authorization ──────────────────────────────────────────────────

    pub fn authorize_travel(
        env: Env,
        caller: Address,
        holder: Address,
        from_jurisdiction: Bytes,
        to_jurisdiction: Bytes,
        purpose: Bytes,
        duration_secs: u64,
    ) -> Result<u64, GeographicError> {
        caller.require_auth();

        let config = Self::get_config(env.clone());
        if duration_secs > config.max_travel_duration_secs {
            return Err(GeographicError::TravelNotAuthorized);
        }

        let travel_idx: Vec<u64> = env.storage().persistent()
            .get(&GeoKey::TravelLogIndex(holder.clone()))
            .unwrap_or_else(|| Vec::new(&env));
        if travel_idx.len() as u32 >= MAX_TRAVEL_ENTRIES {
            return Err(GeographicError::MaxTravelEntriesReached);
        }

        let now = env.ledger().timestamp();
        let travel_key = GeoKey::TravelLog(holder.clone(), now);

        let authorization = TravelAuthorization {
            holder: holder.clone(),
            from_jurisdiction: from_jurisdiction.clone(),
            to_jurisdiction: to_jurisdiction.clone(),
            authorized_at: now,
            expires_at: now + duration_secs,
            purpose: purpose.clone(),
            approved: true,
            approved_by: Some(caller),
        };

        Self::persist(&env, &travel_key, &authorization);

        let mut idx = travel_idx;
        idx.push_back(now);
        Self::persist(&env, &GeoKey::TravelLogIndex(holder), &idx);

        env.events().publish(
            (Symbol::new(&env, "travel_authorized"),),
            (holder, from_jurisdiction, to_jurisdiction),
        );

        Ok(now)
    }

    pub fn get_travel_authorizations(env: Env, holder: Address) -> Vec<u64> {
        env.storage().persistent()
            .get(&GeoKey::TravelLogIndex(holder))
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn get_travel_authorization(env: Env, holder: Address, timestamp: u64) -> Option<TravelAuthorization> {
        env.storage().persistent().get(&GeoKey::TravelLog(holder, timestamp))
    }

    // ── Restricted regions ────────────────────────────────────────────────────

    pub fn add_restricted_region(
        env: Env,
        caller: Address,
        region_code: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }
        let key = GeoKey::RestrictedRegion(region_code.clone());
        if env.storage().persistent().has(&key) {
            return Err(GeographicError::AlreadyExists);
        }
        Self::persist(&env, &key, &true);
        Ok(())
    }

    pub fn remove_restricted_region(
        env: Env,
        caller: Address,
        region_code: Bytes,
    ) -> Result<(), GeographicError> {
        caller.require_auth();
        let admin = Self::require_admin(&env)?;
        if caller != admin {
            return Err(GeographicError::Unauthorized);
        }
        let key = GeoKey::RestrictedRegion(region_code);
        if !env.storage().persistent().has(&key) {
            return Err(GeographicError::NotFound);
        }
        env.storage().persistent().remove(&key);
        Ok(())
    }

    pub fn is_restricted_region(env: Env, region_code: Bytes) -> bool {
        env.storage().persistent().has(&GeoKey::RestrictedRegion(region_code))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env) -> Result<Address, GeographicError> {
        env.storage().instance()
            .get::<Symbol, Address>(&Symbol::new(env, KEY_ADMIN))
            .ok_or(GeographicError::NotInitialized)
    }

    fn persist<K, V>(env: &Env, key: &K, value: &V)
    where
        K: soroban_sdk::TryIntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
        V: soroban_sdk::TryIntoVal<Env, soroban_sdk::Val>
            + soroban_sdk::IntoVal<Env, soroban_sdk::Val>,
    {
        env.storage().persistent().set(key, value);
        env.storage()
            .persistent()
            .extend_ttl(key, GEO_TTL_LEDGERS, GEO_TTL_LEDGERS);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};
    use soroban_sdk::{Address, Bytes, Env, Map, Symbol};

    fn setup_env() -> Env {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set(LedgerInfo {
            timestamp: 1_700_000_000,
            protocol_version: 22,
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });
        env
    }

    fn bootstrap(env: &Env) -> Address {
        let admin = Address::generate(env);
        GeographicRestriction::initialize(env.clone(), admin.clone()).unwrap();
        admin
    }

    fn register_us(env: &Env, admin: &Address) -> Bytes {
        let code = Bytes::from_slice(env, b"US");
        GeographicRestriction::register_jurisdiction(
            env.clone(),
            admin.clone(),
            code.clone(),
            Bytes::from_slice(env, b"United States"),
            Bytes::from_slice(env, b"NA"),
            RestrictionLevel::Allowed,
            Bytes::from_slice(env, b"FINRA"),
        ).unwrap();
        code
    }

    fn register_eu(env: &Env, admin: &Address) -> Bytes {
        let code = Bytes::from_slice(env, b"EU");
        GeographicRestriction::register_jurisdiction(
            env.clone(),
            admin.clone(),
            code.clone(),
            Bytes::from_slice(env, b"European Union"),
            Bytes::from_slice(env, b"EU"),
            RestrictionLevel::Allowed,
            Bytes::from_slice(env, b"ESMA"),
        ).unwrap();
        code
    }

    #[test]
    fn initializes_successfully() {
        let env = setup_env();
        let admin = Address::generate(&env);
        assert!(GeographicRestriction::initialize(env, admin).is_ok());
    }

    #[test]
    fn double_initialize_returns_error() {
        let env = setup_env();
        bootstrap(&env);
        let result = GeographicRestriction::initialize(env.clone(), Address::generate(&env));
        assert_eq!(result.unwrap_err(), GeographicError::AlreadyInitialized);
    }

    #[test]
    fn register_and_retrieve_jurisdiction() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let code = register_us(&env, &admin);

        let jur = GeographicRestriction::get_jurisdiction(env, code).unwrap();
        assert!(jur.active);
        assert_eq!(jur.restriction_level, RestrictionLevel::Allowed);
    }

    #[test]
    fn duplicate_jurisdiction_returns_error() {
        let env = setup_env();
        let admin = bootstrap(&env);
        register_us(&env, &admin);

        let result = GeographicRestriction::register_jurisdiction(
            env.clone(),
            admin,
            Bytes::from_slice(&env, b"US"),
            Bytes::from_slice(&env, b"USA"),
            Bytes::from_slice(&env, b"NA"),
            RestrictionLevel::Allowed,
            Bytes::from_slice(&env, b"SEC"),
        );
        assert_eq!(result.unwrap_err(), GeographicError::AlreadyExists);
    }

    #[test]
    fn deactivate_jurisdiction() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let code = register_us(&env, &admin);

        GeographicRestriction::deactivate_jurisdiction(env.clone(), admin, code.clone()).unwrap();
        let jur = GeographicRestriction::get_jurisdiction(env, code).unwrap();
        assert!(!jur.active);
    }

    #[test]
    fn geo_tag_creation_and_retrieval() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let us = register_us(&env, &admin);
        let eu = register_eu(&env, &admin);

        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-001");
        let mut metadata = Map::new(&env);
        metadata.set(Symbol::new(&env, "type"), Bytes::from_slice(&env, b"kyc"));

        GeographicRestriction::create_geo_tag(
            env.clone(),
            holder,
            cred_id.clone(),
            us.clone(),
            eu.clone(),
            2,
            metadata,
            1_800_000_000,
        ).unwrap();

        let tag = GeographicRestriction::get_geo_tag(env, cred_id).unwrap();
        assert!(tag.active);
        assert_eq!(tag.issuing_jurisdiction, us);
        assert_eq!(tag.holder_jurisdiction, eu);
    }

    #[test]
    fn restricted_jurisdiction_blocks_usage() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let blocked_code = Bytes::from_slice(&env, b"XX");
        GeographicRestriction::register_jurisdiction(
            env.clone(),
            admin.clone(),
            blocked_code.clone(),
            Bytes::from_slice(&env, b"Blocked"),
            Bytes::from_slice(&env, b"XX"),
            RestrictionLevel::Blocked,
            Bytes::from_slice(&env, b"None"),
        ).unwrap();

        let us = register_us(&env, &admin);
        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-002");

        GeographicRestriction::create_geo_tag(
            env.clone(),
            holder,
            cred_id.clone(),
            us,
            blocked_code.clone(),
            1,
            Map::new(&env),
            1_800_000_000,
        ).unwrap();

        let result = GeographicRestriction::verify_geographic_usage(
            env.clone(),
            cred_id,
            Bytes::from_slice(&env, b"kyc"),
            blocked_code,
        );
        assert_eq!(result.unwrap_err(), GeographicError::JurisdictionBlocked);
    }

    #[test]
    fn restriction_rule_blocks_cross_border() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let us = register_us(&env, &admin);
        let eu = register_eu(&env, &admin);

        GeographicRestriction::register_restriction_rule(
            env.clone(),
            admin.clone(),
            us.clone(),
            eu.clone(),
            RestrictionLevel::Blocked,
            Bytes::from_slice(&env, b"kyc"),
            false,
            0,
        ).unwrap();

        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-003");

        GeographicRestriction::create_geo_tag(
            env.clone(),
            holder,
            cred_id.clone(),
            us.clone(),
            us,
            1,
            Map::new(&env),
            1_800_000_000,
        ).unwrap();

        let result = GeographicRestriction::verify_geographic_usage(
            env.clone(),
            cred_id,
            Bytes::from_slice(&env, b"kyc"),
            eu,
        );
        assert_eq!(result.unwrap_err(), GeographicError::CrossBorderRestriction);
    }

    #[test]
    fn geo_tag_expiration() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let us = register_us(&env, &admin);

        let holder = Address::generate(&env);
        let cred_id = Bytes::from_slice(&env, b"cred-expired");

        GeographicRestriction::create_geo_tag(
            env.clone(),
            holder.clone(),
            cred_id.clone(),
            us.clone(),
            us,
            1,
            Map::new(&env),
            1_700_000_001,
        ).unwrap();

        let future_time = 1_800_000_000u64;
        env.ledger().set(LedgerInfo {
            timestamp: future_time,
            protocol_version: 22,
            sequence_number: 5000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 50_000,
            min_persistent_entry_ttl: 50_000,
            max_entry_ttl: 50_000,
        });

        let result = GeographicRestriction::verify_geographic_usage(
            env.clone(),
            cred_id,
            Bytes::from_slice(&env, b"kyc"),
            us,
        );
        assert_eq!(result.unwrap_err(), GeographicError::ExpiredGeoTag);
    }

    #[test]
    fn travel_authorization() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let us = register_us(&env, &admin);
        let eu = register_eu(&env, &admin);

        let holder = Address::generate(&env);

        let ts = GeographicRestriction::authorize_travel(
            env.clone(),
            admin.clone(),
            holder.clone(),
            us,
            eu,
            Bytes::from_slice(&env, b"business"),
            7 * 24 * 60 * 60,
        ).unwrap();

        let auth = GeographicRestriction::get_travel_authorization(env.clone(), holder.clone(), ts).unwrap();
        assert!(auth.approved);
        assert_eq!(auth.purpose, Bytes::from_slice(&env, b"business"));

        let travel_log = GeographicRestriction::get_travel_authorizations(env, holder);
        assert_eq!(travel_log.len(), 1);
    }

    #[test]
    fn travel_exceeds_max_duration() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let us = register_us(&env, &admin);
        let eu = register_eu(&env, &admin);
        let holder = Address::generate(&env);

        let result = GeographicRestriction::authorize_travel(
            env.clone(),
            admin,
            holder,
            us,
            eu,
            Bytes::from_slice(&env, b"long_stay"),
            200 * 24 * 60 * 60,
        );
        assert_eq!(result.unwrap_err(), GeographicError::TravelNotAuthorized);
    }

    #[test]
    fn restricted_region_management() {
        let env = setup_env();
        let admin = bootstrap(&env);

        let region = Bytes::from_slice(&env, b"KR");
        GeographicRestriction::add_restricted_region(env.clone(), admin.clone(), region.clone()).unwrap();
        assert!(GeographicRestriction::is_restricted_region(env.clone(), region.clone()));

        GeographicRestriction::remove_restricted_region(env.clone(), admin, region.clone()).unwrap();
        assert!(!GeographicRestriction::is_restricted_region(env, region));
    }

    #[test]
    fn config_update() {
        let env = setup_env();
        let admin = bootstrap(&env);

        GeographicRestriction::update_config(
            env.clone(),
            admin,
            Some(true),
            Some(false),
            Some(false),
            Some(60 * 24 * 60 * 60),
            Some(15 * 24 * 60 * 60),
        ).unwrap();

        let config = GeographicRestriction::get_config(env);
        assert!(!config.default_verification_required);
        assert!(!config.travel_notification_required);
        assert_eq!(config.max_travel_duration_secs, 60 * 24 * 60 * 60);
    }

    #[test]
    fn cross_border_policy() {
        let env = setup_env();
        let admin = bootstrap(&env);
        let us = register_us(&env, &admin);
        let eu = register_eu(&env, &admin);

        GeographicRestriction::set_cross_border_policy(
            env.clone(),
            admin,
            us.clone(),
            eu,
            RestrictionLevel::RequiresApproval,
            true,
            5,
            true,
        ).unwrap();

        let policy = GeographicRestriction::get_cross_border_policy(env, us).unwrap();
        assert_eq!(policy.policy, RestrictionLevel::RequiresApproval);
        assert!(policy.requires_visa);
    }

    #[test]
    fn non_admin_cannot_register_jurisdiction() {
        let env = setup_env();
        bootstrap(&env);
        let intruder = Address::generate(&env);

        let result = GeographicRestriction::register_jurisdiction(
            env.clone(),
            intruder,
            Bytes::from_slice(&env, b"US"),
            Bytes::from_slice(&env, b"United States"),
            Bytes::from_slice(&env, b"NA"),
            RestrictionLevel::Allowed,
            Bytes::from_slice(&env, b"FINRA"),
        );
        assert_eq!(result.unwrap_err(), GeographicError::Unauthorized);
    }

    #[test]
    fn get_all_jurisdictions() {
        let env = setup_env();
        let admin = bootstrap(&env);
        register_us(&env, &admin);
        register_eu(&env, &admin);

        let all = GeographicRestriction::get_all_jurisdictions(env);
        assert_eq!(all.len(), 2);
    }
}
