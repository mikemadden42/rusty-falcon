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
pub struct FalconxPeriodExtractedFile {
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        rename = "file_available_to_download",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_available_to_download: Option<bool>,
    #[serde(rename = "file_path", skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(rename = "file_size", skip_serializing_if = "Option::is_none")]
    pub file_size: Option<i32>,
    #[serde(rename = "md5", skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "runtime_process", skip_serializing_if = "Option::is_none")]
    pub runtime_process: Option<String>,
    #[serde(rename = "sha1", skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(rename = "sha256", skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(rename = "threat_level", skip_serializing_if = "Option::is_none")]
    pub threat_level: Option<i32>,
    #[serde(
        rename = "threat_level_readable",
        skip_serializing_if = "Option::is_none"
    )]
    pub threat_level_readable: Option<String>,
    #[serde(rename = "type_tags", skip_serializing_if = "Option::is_none")]
    pub type_tags: Option<Vec<String>>,
}

impl FalconxPeriodExtractedFile {
    pub fn new() -> FalconxPeriodExtractedFile {
        FalconxPeriodExtractedFile {
            description: None,
            file_available_to_download: None,
            file_path: None,
            file_size: None,
            md5: None,
            name: None,
            runtime_process: None,
            sha1: None,
            sha256: None,
            threat_level: None,
            threat_level_readable: None,
            type_tags: None,
        }
    }
}