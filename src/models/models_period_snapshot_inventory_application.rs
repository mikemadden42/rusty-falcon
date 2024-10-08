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
pub struct ModelsPeriodSnapshotInventoryApplication {
    #[serde(rename = "major_version")]
    pub major_version: String,
    #[serde(rename = "package_hash")]
    pub package_hash: String,
    #[serde(rename = "package_provider")]
    pub package_provider: String,
    #[serde(rename = "package_source")]
    pub package_source: String,
    #[serde(rename = "path")]
    pub path: String,
    #[serde(rename = "product")]
    pub product: String,
    #[serde(rename = "software_architecture")]
    pub software_architecture: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "vendor")]
    pub vendor: String,
}

impl ModelsPeriodSnapshotInventoryApplication {
    pub fn new(
        major_version: String,
        package_hash: String,
        package_provider: String,
        package_source: String,
        path: String,
        product: String,
        software_architecture: String,
        r#type: String,
        vendor: String,
    ) -> ModelsPeriodSnapshotInventoryApplication {
        ModelsPeriodSnapshotInventoryApplication {
            major_version,
            package_hash,
            package_provider,
            package_source,
            path,
            product,
            software_architecture,
            r#type,
            vendor,
        }
    }
}
