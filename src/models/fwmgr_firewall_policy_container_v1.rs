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
pub struct FwmgrFirewallPolicyContainerV1 {
    #[serde(rename = "created_by", skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    #[serde(rename = "created_on", skip_serializing_if = "Option::is_none")]
    pub created_on: Option<String>,
    #[serde(rename = "default_inbound")]
    pub default_inbound: String,
    #[serde(rename = "default_outbound")]
    pub default_outbound: String,
    #[serde(rename = "deleted", skip_serializing_if = "Option::is_none")]
    pub deleted: Option<bool>,
    #[serde(rename = "enforce")]
    pub enforce: bool,
    #[serde(rename = "is_default_policy", skip_serializing_if = "Option::is_none")]
    pub is_default_policy: Option<bool>,
    #[serde(rename = "modified_by", skip_serializing_if = "Option::is_none")]
    pub modified_by: Option<String>,
    #[serde(rename = "modified_on", skip_serializing_if = "Option::is_none")]
    pub modified_on: Option<String>,
    #[serde(rename = "platform_id")]
    pub platform_id: String,
    #[serde(rename = "policy_id")]
    pub policy_id: String,
    #[serde(rename = "rule_group_ids")]
    pub rule_group_ids: Vec<String>,
    #[serde(rename = "test_mode")]
    pub test_mode: bool,
    #[serde(rename = "tracking", skip_serializing_if = "Option::is_none")]
    pub tracking: Option<String>,
}

impl FwmgrFirewallPolicyContainerV1 {
    pub fn new(default_inbound: String, default_outbound: String, enforce: bool, platform_id: String, policy_id: String, rule_group_ids: Vec<String>, test_mode: bool) -> FwmgrFirewallPolicyContainerV1 {
        FwmgrFirewallPolicyContainerV1 {
            created_by: None,
            created_on: None,
            default_inbound,
            default_outbound,
            deleted: None,
            enforce,
            is_default_policy: None,
            modified_by: None,
            modified_on: None,
            platform_id,
            policy_id,
            rule_group_ids,
            test_mode,
            tracking: None,
        }
    }
}


