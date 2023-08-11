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
pub struct FalconxStream {
    #[serde(rename = "executed", skip_serializing_if = "Option::is_none")]
    pub executed: Option<bool>,
    #[serde(rename = "file_name", skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(rename = "human_keywords", skip_serializing_if = "Option::is_none")]
    pub human_keywords: Option<String>,
    #[serde(
        rename = "instructions_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub instructions_artifact_id: Option<String>,
    #[serde(rename = "matched_signatures", skip_serializing_if = "Option::is_none")]
    pub matched_signatures: Option<Vec<crate::models::FalconxMatchedSignature>>,
    #[serde(rename = "uid", skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
}

impl FalconxStream {
    pub fn new() -> FalconxStream {
        FalconxStream {
            executed: None,
            file_name: None,
            human_keywords: None,
            instructions_artifact_id: None,
            matched_signatures: None,
            uid: None,
        }
    }
}
