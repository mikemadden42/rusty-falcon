/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and examples, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation).     To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`.    Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: rolling
 *
 * Generated by: https://openapi-generator.tech
 */

#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub struct DomainPeriodExternalAssetCloudVm {
    /// The VM description
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The ID of the cloud VM
    #[serde(rename = "instance_id", skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
    /// The lifecycle phase
    #[serde(rename = "lifecycle", skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<String>,
    /// MAC address of the VM
    #[serde(rename = "mac_address", skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,
    /// VM owner ID
    #[serde(rename = "owner_id", skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    /// VM platform information
    #[serde(rename = "platform", skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// VM private IP address
    #[serde(rename = "private_ip", skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    /// VM public IP address
    #[serde(rename = "public_ip", skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,
    /// The cloud region
    #[serde(rename = "region", skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Security groups
    #[serde(rename = "security_groups", skip_serializing_if = "Option::is_none")]
    pub security_groups: Option<Vec<String>>,
    /// The VM source image
    #[serde(rename = "source", skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Connectivity status of the cloud VM
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

impl DomainPeriodExternalAssetCloudVm {
    pub fn new() -> DomainPeriodExternalAssetCloudVm {
        DomainPeriodExternalAssetCloudVm {
            description: None,
            instance_id: None,
            lifecycle: None,
            mac_address: None,
            owner_id: None,
            platform: None,
            private_ip: None,
            public_ip: None,
            region: None,
            security_groups: None,
            source: None,
            status: None,
        }
    }
}