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
pub struct FalconxPeriodMemoryDumpData {
    #[serde(rename = "address", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(rename = "binary_content_id", skip_serializing_if = "Option::is_none")]
    pub binary_content_id: Option<String>,
    #[serde(
        rename = "extracted_strings_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub extracted_strings_id: Option<String>,
    #[serde(rename = "file_process", skip_serializing_if = "Option::is_none")]
    pub file_process: Option<String>,
    #[serde(
        rename = "file_process_disc_pathway",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_process_disc_pathway: Option<String>,
    #[serde(rename = "file_process_pid", skip_serializing_if = "Option::is_none")]
    pub file_process_pid: Option<i32>,
    #[serde(
        rename = "file_process_sha256",
        skip_serializing_if = "Option::is_none"
    )]
    pub file_process_sha256: Option<String>,
    #[serde(rename = "filename", skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    #[serde(rename = "flags", skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
    #[serde(rename = "hex_dump_id", skip_serializing_if = "Option::is_none")]
    pub hex_dump_id: Option<String>,
    #[serde(rename = "verdict", skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
}

impl FalconxPeriodMemoryDumpData {
    pub fn new() -> FalconxPeriodMemoryDumpData {
        FalconxPeriodMemoryDumpData {
            address: None,
            binary_content_id: None,
            extracted_strings_id: None,
            file_process: None,
            file_process_disc_pathway: None,
            file_process_pid: None,
            file_process_sha256: None,
            filename: None,
            flags: None,
            hex_dump_id: None,
            verdict: None,
        }
    }
}