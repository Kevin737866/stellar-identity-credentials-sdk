#[cfg(test)]
mod tests {
    use crate::dif_interop::{DidCommMessage, PresentationDefinitionV2, InputDescriptor, Constraints, Field, SchemaFilter};
    use std::collections::HashMap;

    #[test]
    fn test_didcomm_v2_formatting() {
        let mut body = HashMap::new();
        body.insert("status".to_string(), serde_json::json!("Active"));

        let message = DidCommMessage::new(
            "urn:uuid:test-001",
            "https://didcomm.org/discover-features/2.0/queries",
            Some("did:stellar:sender".to_string()),
            vec!["did:stellar:receiver".to_string()],
            body
        );

        assert_eq!(message.id, "urn:uuid:test-001");
        assert!(message.expires_time.unwrap() > message.created_time.unwrap());
    }

    #[test]
    fn test_presentation_exchange_v2_matching() {
        let definition = PresentationDefinitionV2 {
            id: "test_query_id".to_string(),
            input_descriptors: vec![InputDescriptor {
                id: "kyc_data".to_string(),
                purpose: Some("Verification".to_string()),
                schema: vec![SchemaFilter { uri: "https://schema.org/Kyc".to_string() }],
                constraints: Some(Constraints {
                    fields: Some(vec![Field {
                        path: vec!["$.credentialSubject.is_adult".to_string()],
                    }]),
                }),
            }],
        };

        let mut matching_claims = HashMap::new();
        matching_claims.insert("is_adult".to_string(), serde_json::json!(true));

        let mut failing_claims = HashMap::new();
        failing_claims.insert("legacy_user".to_string(), serde_json::json!(false));

        assert!(definition.evaluate_claims(&matching_claims));
        assert!(!definition.evaluate_claims(&failing_claims));
    }
}