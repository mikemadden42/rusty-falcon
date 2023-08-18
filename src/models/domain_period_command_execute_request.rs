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
pub struct DomainPeriodCommandExecuteRequest {
    #[serde(rename = "base_command")]
    pub base_command: String,
    #[serde(rename = "command_string")]
    pub command_string: String,
    #[serde(rename = "device_id")]
    pub device_id: String,
    #[serde(rename = "id")]
    pub id: i32,
    #[serde(rename = "persist")]
    pub persist: bool,
    #[serde(rename = "session_id")]
    pub session_id: String,
}

impl DomainPeriodCommandExecuteRequest {
    pub fn new(
        base_command: String,
        command_string: String,
        device_id: String,
        id: i32,
        persist: bool,
        session_id: String,
    ) -> DomainPeriodCommandExecuteRequest {
        DomainPeriodCommandExecuteRequest {
            base_command,
            command_string,
            device_id,
            id,
            persist,
            session_id,
        }
    }
}