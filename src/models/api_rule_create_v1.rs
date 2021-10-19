/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2021-10-05T19:33:53Z
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct ApiRuleCreateV1 {
    #[serde(rename = "comment")]
    pub comment: String,
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "disposition_id")]
    pub disposition_id: i32,
    #[serde(rename = "field_values")]
    pub field_values: Vec<crate::models::DomainFieldValue>,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "pattern_severity")]
    pub pattern_severity: String,
    #[serde(rename = "rulegroup_id")]
    pub rulegroup_id: String,
    #[serde(rename = "ruletype_id")]
    pub ruletype_id: String,
}

impl ApiRuleCreateV1 {
    pub fn new(comment: String, description: String, disposition_id: i32, field_values: Vec<crate::models::DomainFieldValue>, name: String, pattern_severity: String, rulegroup_id: String, ruletype_id: String) -> ApiRuleCreateV1 {
        ApiRuleCreateV1 {
            comment,
            description,
            disposition_id,
            field_values,
            name,
            pattern_severity,
            rulegroup_id,
            ruletype_id,
        }
    }
}


