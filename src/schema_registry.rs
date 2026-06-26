use soroban_sdk::{contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Symbol};

use crate::CredentialSchema;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SchemaRegistryError {
    AlreadyExists = 1,
    NotFound = 2,
    Unauthorized = 3,
    InvalidFormat = 4,
}

#[contract]
pub struct CredentialSchemaRegistry;

#[contracttype]
#[derive(Clone)]
pub enum SchemaKey {
    Version(Bytes),
    Schema(Bytes, u32),
}


#[contractimpl]
impl CredentialSchemaRegistry {
    const MAX_SCHEMA_ID_LENGTH: u32 = 128;
    const MAX_DEFINITION_LENGTH: u32 = 10240;

    /// Register a new credential schema.
    pub fn register_schema(
        env: Env,
        issuer: Address,
        schema_id: Bytes,
        definition: Bytes,
    ) -> Result<(), SchemaRegistryError> {
        issuer.require_auth();

        if schema_id.len() > Self::MAX_SCHEMA_ID_LENGTH {
            return Err(SchemaRegistryError::InvalidFormat);
        }

        if definition.len() > Self::MAX_DEFINITION_LENGTH {
            return Err(SchemaRegistryError::InvalidFormat);
        }

        let version_key = Self::get_version_key(&env, &schema_id, 1);
        if env.storage().persistent().has(&version_key) {
            return Err(SchemaRegistryError::AlreadyExists);
        }

        let now = env.ledger().timestamp();
        let schema = CredentialSchema {
            id: schema_id.clone(),
            issuer: issuer.clone(),
            version: 1,
            definition,
            created: now,
            updated: now,
        };

        env.storage().persistent().set(&version_key, &schema);

        // Store current version
        env.storage().persistent().set(
            &Symbol::new(&env, &format!("version:{}", "<bytes>")),
            &1u32,
        );

        Ok(())
    }

    /// Update an existing credential schema, incrementing its version.
    pub fn update_schema(
        env: Env,
        issuer: Address,
        schema_id: Bytes,
        definition: Bytes,
    ) -> Result<(), SchemaRegistryError> {
        issuer.require_auth();

        let current_version: u32 = env
            .storage()
            .persistent()
            .get(&SchemaKey::Version(schema_id.clone()))
            .ok_or(SchemaRegistryError::NotFound)?;

        let last_version_key = Self::get_version_key(&env, &schema_id, current_version);
        let last_schema: CredentialSchema = env
            .storage()
            .persistent()
            .get(&last_version_key)
            .ok_or(SchemaRegistryError::NotFound)?;

        if last_schema.issuer != issuer {
            return Err(SchemaRegistryError::Unauthorized);
        }

        if definition.len() > Self::MAX_DEFINITION_LENGTH {
            return Err(SchemaRegistryError::InvalidFormat);
        }

        let new_version = current_version + 1;
        let new_version_key = Self::get_version_key(&env, &schema_id, new_version);

        let now = env.ledger().timestamp();
        let schema = CredentialSchema {
            id: schema_id.clone(),
            issuer,
            version: new_version,
            definition,
            created: last_schema.created,
            updated: now,
        };

        env.storage().persistent().set(&new_version_key, &schema);
        env.storage().persistent().set(
            &Symbol::new(&env, &format!("version:{}", "<bytes>")),
            &new_version,
        );

        Ok(())
    }

    /// Resolve a specific version of a schema, or the latest if version is None.
    pub fn get_schema(
        env: Env,
        schema_id: Bytes,
        version: Option<u32>,
    ) -> Result<CredentialSchema, SchemaRegistryError> {
        let target_version = match version {
            Some(v) => v,
            None => env
                .storage()
                .persistent()
                .get(&SchemaKey::Version(schema_id.clone()))
                .ok_or(SchemaRegistryError::NotFound)?,
        };

        let version_key = Self::get_version_key(&env, &schema_id, target_version);
        env.storage()
            .persistent()
            .get(&version_key)
            .ok_or(SchemaRegistryError::NotFound)
    }

    /// Basic validation logic: check if a credential's schema exists and is active.
    /// In a real world scenario, this would parse the definition and validate claims.
    pub fn validate_schema_exists(env: Env, schema_id: Bytes) -> Result<bool, SchemaRegistryError> {
        Self::get_schema(env, schema_id, None).map(|_| true)
    }

    fn get_version_key(env: &Env, schema_id: &Bytes, version: u32) -> Symbol {
        SchemaKey::Schema(schema_id.clone(), version)
    }
}
