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
pub struct K8sregPeriodAzureSubscriptionResp {
    #[serde(rename = "azure_permissions_status")]
    pub azure_permissions_status: Vec<crate::models::K8sregPeriodAccountPermissionsStatus>,
    #[serde(rename = "created_at")]
    pub created_at: String,
    #[serde(rename = "from_cspm")]
    pub from_cspm: bool,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "subscription_id")]
    pub subscription_id: String,
    #[serde(rename = "tenant_id")]
    pub tenant_id: String,
    #[serde(rename = "updated_at")]
    pub updated_at: String,
}

impl K8sregPeriodAzureSubscriptionResp {
    pub fn new(
        azure_permissions_status: Vec<crate::models::K8sregPeriodAccountPermissionsStatus>,
        created_at: String,
        from_cspm: bool,
        status: String,
        subscription_id: String,
        tenant_id: String,
        updated_at: String,
    ) -> K8sregPeriodAzureSubscriptionResp {
        K8sregPeriodAzureSubscriptionResp {
            azure_permissions_status,
            created_at,
            from_cspm,
            status,
            subscription_id,
            tenant_id,
            updated_at,
        }
    }
}