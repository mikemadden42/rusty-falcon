/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2023-08-08T23:00:01Z
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct SadomainPeriodRule {
    /// Whether to monitor for breach data. Available only for `Company Domains` and `Email addresses` rule topics. When enabled, ownership of the monitored domains or emails is required
    #[serde(rename = "breach_monitoring_enabled")]
    pub breach_monitoring_enabled: bool,
    #[serde(rename = "cid")]
    pub cid: String,
    /// The creation time for a given rule
    #[serde(rename = "created_timestamp")]
    pub created_timestamp: String,
    /// The FQL filter contained in a rule and used for searching. Parentheses may be added automatically for clarity
    #[serde(rename = "filter")]
    pub filter: String,
    /// The ID of a given rule
    #[serde(rename = "id")]
    pub id: String,
    /// The name of a given rule
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ownership_assets", skip_serializing_if = "Option::is_none")]
    pub ownership_assets: Option<Box<crate::models::SadomainPeriodCustomerAssets>>,
    /// The permissions of a given rule
    #[serde(rename = "permissions")]
    pub permissions: String,
    /// The priority of a given rule
    #[serde(rename = "priority")]
    pub priority: String,
    /// The status of a given rule
    #[serde(rename = "status")]
    pub status: String,
    /// The detailed status message of a given rule
    #[serde(rename = "status_message", skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    /// Whether to monitor for substring matches. Only available for the `Typosquatting` rule topic
    #[serde(rename = "substring_matching_enabled")]
    pub substring_matching_enabled: bool,
    /// The topic of a given rule
    #[serde(rename = "topic")]
    pub topic: String,
    /// The last updated time for a given rule
    #[serde(rename = "updated_timestamp")]
    pub updated_timestamp: String,
    /// The user ID of the user that created a given rule
    #[serde(rename = "user_id", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// The user name of the user that created a given rule
    #[serde(rename = "user_name", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    /// The UUID of the user that created a given rule
    #[serde(rename = "user_uuid")]
    pub user_uuid: String,
}

impl SadomainPeriodRule {
    pub fn new(
        breach_monitoring_enabled: bool,
        cid: String,
        created_timestamp: String,
        filter: String,
        id: String,
        name: String,
        permissions: String,
        priority: String,
        status: String,
        substring_matching_enabled: bool,
        topic: String,
        updated_timestamp: String,
        user_uuid: String,
    ) -> SadomainPeriodRule {
        SadomainPeriodRule {
            breach_monitoring_enabled,
            cid,
            created_timestamp,
            filter,
            id,
            name,
            ownership_assets: None,
            permissions,
            priority,
            status,
            status_message: None,
            substring_matching_enabled,
            topic,
            updated_timestamp,
            user_id: None,
            user_name: None,
            user_uuid,
        }
    }
}