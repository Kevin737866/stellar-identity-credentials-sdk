use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, Bytes, Env, Vec,
};

use crate::CredentialSchema;

#[contracttype]
#[derive(Clone)]
enum SchemaKey {
    Version(Bytes, u32),
    LatestVersion(Bytes),
}

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

#[contractimpl]
impl CredentialSchemaRegistry {
    const MAX_SCHEMA_ID_LENGTH: u32 = 128;
    const MAX_DEFINITION_LENGTH: u32 = 10240;

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

        if env
            .storage()
            .persistent()
            .has(&SchemaKey::LatestVersion(schema_id.clone()))
        {
            return Err(SchemaRegistryError::AlreadyExists);
        }

        let now = env.ledger().timestamp();
        let schema = CredentialSchema {
            id: schema_id.clone(),
            issuer,
            version: 1,
            definition,
            created: now,
            updated: now,
        };

        env.storage()
            .persistent()
            .set(&SchemaKey::Version(schema_id.clone(), 1), &schema);
        env.storage()
            .persistent()
            .set(&SchemaKey::LatestVersion(schema_id), &1u32);

        Ok(())
    }

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
            .get(&SchemaKey::LatestVersion(schema_id.clone()))
            .ok_or(SchemaRegistryError::NotFound)?;

        let last_schema: CredentialSchema = env
            .storage()
            .persistent()
            .get(&SchemaKey::Version(schema_id.clone(), current_version))
            .ok_or(SchemaRegistryError::NotFound)?;

        if last_schema.issuer != issuer {
            return Err(SchemaRegistryError::Unauthorized);
        }
        if definition.len() > Self::MAX_DEFINITION_LENGTH {
            return Err(SchemaRegistryError::InvalidFormat);
        }

        let new_version = current_version + 1;
        let now = env.ledger().timestamp();
        let schema = CredentialSchema {
            id: schema_id.clone(),
            issuer,
            version: new_version,
            definition,
            created: last_schema.created,
            updated: now,
        };

        env.storage()
            .persistent()
            .set(&SchemaKey::Version(schema_id.clone(), new_version), &schema);
        env.storage()
            .persistent()
            .set(&SchemaKey::LatestVersion(schema_id), &new_version);

        Ok(())
    }

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
                .get(&SchemaKey::LatestVersion(schema_id.clone()))
                .ok_or(SchemaRegistryError::NotFound)?,
        };

        env.storage()
            .persistent()
            .get(&SchemaKey::Version(schema_id, target_version))
            .ok_or(SchemaRegistryError::NotFound)
    }

    pub fn validate_schema_exists(
        env: Env,
        schema_id: Bytes,
    ) -> Result<bool, SchemaRegistryError> {
        Self::get_schema(env, schema_id, None).map(|_| true)
    }
}
