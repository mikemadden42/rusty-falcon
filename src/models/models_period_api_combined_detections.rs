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
pub struct ModelsPeriodApiCombinedDetections {
    #[serde(rename = "cid")]
    pub cid: String,
    #[serde(rename = "containers_impacted")]
    pub containers_impacted: i64,
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "details")]
    pub details: Vec<String>,
    #[serde(rename = "detection_id")]
    pub detection_id: String,
    #[serde(rename = "detection_name")]
    pub detection_name: String,
    #[serde(rename = "detection_severity")]
    pub detection_severity: String,
    #[serde(rename = "detection_type")]
    pub detection_type: String,
    #[serde(rename = "images_impacted")]
    pub images_impacted: i64,
    #[serde(rename = "last_detected")]
    pub last_detected: String,
    #[serde(rename = "remediation")]
    pub remediation: String,
    #[serde(rename = "title")]
    pub title: String,
}

impl ModelsPeriodApiCombinedDetections {
    pub fn new(
        cid: String,
        containers_impacted: i64,
        description: String,
        details: Vec<String>,
        detection_id: String,
        detection_name: String,
        detection_severity: String,
        detection_type: String,
        images_impacted: i64,
        last_detected: String,
        remediation: String,
        title: String,
    ) -> ModelsPeriodApiCombinedDetections {
        ModelsPeriodApiCombinedDetections {
            cid,
            containers_impacted,
            description,
            details,
            detection_id,
            detection_name,
            detection_severity,
            detection_type,
            images_impacted,
            last_detected,
            remediation,
            title,
        }
    }
}