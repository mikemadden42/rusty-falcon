/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainRule {
    /// The categories associated with the rule
    #[serde(rename = "categories")]
    pub categories: Vec<String>,
    /// UTC timestamp when rule was created
    #[serde(rename = "created_date")]
    pub created_date: String,
    /// The ID of the customer
    #[serde(rename = "customer_id")]
    pub customer_id: String,
    /// The ID of the rule
    #[serde(rename = "id")]
    pub id: String,
    /// The name of the rule
    #[serde(rename = "name")]
    pub name: String,
    /// The type of the rule
    #[serde(rename = "rule_type")]
    pub rule_type: String,
    /// UTC timestamp when rule was last updated
    #[serde(rename = "updated_date")]
    pub updated_date: String,
    /// The value of the rule
    #[serde(rename = "value")]
    pub value: String,
}

impl DomainRule {
    pub fn new(
        categories: Vec<String>,
        created_date: String,
        customer_id: String,
        id: String,
        name: String,
        rule_type: String,
        updated_date: String,
        value: String,
    ) -> DomainRule {
        DomainRule {
            categories,
            created_date,
            customer_id,
            id,
            name,
            rule_type,
            updated_date,
            value,
        }
    }
}
