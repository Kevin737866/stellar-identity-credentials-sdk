use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ==========================================
// 1. DIDComm v2 Envelope & Message Model
// ==========================================
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DidCommMessage {
    pub id: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    pub to: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_time: Option<u64>,
    pub body: HashMap<String, serde_json::Value>,
}

impl DidCommMessage {
    pub fn new(id: &str, r#type: &str, from: Option<String>, to: Vec<String>, body: HashMap<String, serde_json::Value>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id: id.to_string(),
            r#type: r#type.to_string(),
            from,
            to,
            created_time: Some(now),
            expires_time: Some(now + 3600), // 1 hour TTL default
            body,
        }
    }
}

// ==========================================
// 2. Presentation Exchange v2.0 Specification
// ==========================================
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InputDescriptor {
    pub id: String,
    pub purpose: Option<String>,
    pub schema: Vec<SchemaFilter>,
    pub constraints: Option<Constraints>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SchemaFilter {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Constraints {
    pub fields: Option<Vec<Field>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Field {
    pub path: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PresentationDefinitionV2 {
    pub id: String,
    pub input_descriptors: Vec<InputDescriptor>,
}

impl PresentationDefinitionV2 {
    /// Validates if incoming verifiable credential claims satisfy the required JSONPaths
    pub fn evaluate_claims(&self, claims: &HashMap<String, serde_json::Value>) -> bool {
        for descriptor in &self.input_descriptors {
            if let Some(ref constraints) = descriptor.constraints {
                if let Some(ref fields) = constraints.fields {
                    for field in fields {
                        for path in &field.path {
                            // Strip JSONPath prefix safely to verify the presence of claims
                            let clean_key = path.replace("$.credentialSubject.", "");
                            if !claims.contains_key(&clean_key) {
                                return false; // Missing mandatory claim mapping
                            }
                        }
                    }
                }
            }
        }
        true
    }
}

// ==========================================
// 3. Credential Manifest Specification
// ==========================================
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ManifestIssuer {
    pub id: String,
    pub name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OutputDescriptor {
    pub id: String,
    pub schema: String,
    pub display: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CredentialManifest {
    pub id: String,
    pub issuer: ManifestIssuer,
    pub output_descriptors: Vec<OutputDescriptor>,
}