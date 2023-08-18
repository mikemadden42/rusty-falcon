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
pub struct SadomainPeriodCreateRuleRequestV1 {
    /// Whether to monitor for breach data. Available only for `Company Domains` and `Email addresses` rule topics. When enabled, ownership of the monitored domains or emails is required
    #[serde(rename = "breach_monitoring_enabled")]
    pub breach_monitoring_enabled: bool,
    /// The FQL filter to be used for searching
    #[serde(rename = "filter")]
    pub filter: String,
    /// The name of a given rule
    #[serde(rename = "name")]
    pub name: String,
    /// The permissions for a given rule which specifies the rule's access by other users. Possible values: [`public`, `private`]
    #[serde(rename = "permissions")]
    pub permissions: String,
    /// The priority for a given rule. Possible values: [`low`, `medium`, `high`]
    #[serde(rename = "priority")]
    pub priority: String,
    /// Whether to monitor for substring matches. Only available for the `Typosquatting` topic.
    #[serde(rename = "substring_matching_enabled")]
    pub substring_matching_enabled: bool,
    /// The topic of a given rule. Possible values: [`SA_BRAND_PRODUCT`, `SA_VIP`, `SA_THIRD_PARTY`, `SA_IP`, `SA_CVE`, `SA_BIN`, `SA_DOMAIN`, `SA_EMAIL`, `SA_ALIAS`, `SA_AUTHOR`, `SA_CUSTOM`, `SA_TYPOSQUATTING`]
    #[serde(rename = "topic")]
    pub topic: String,
}

impl SadomainPeriodCreateRuleRequestV1 {
    pub fn new(
        breach_monitoring_enabled: bool,
        filter: String,
        name: String,
        permissions: String,
        priority: String,
        substring_matching_enabled: bool,
        topic: String,
    ) -> SadomainPeriodCreateRuleRequestV1 {
        SadomainPeriodCreateRuleRequestV1 {
            breach_monitoring_enabled,
            filter,
            name,
            permissions,
            priority,
            substring_matching_enabled,
            topic,
        }
    }
}