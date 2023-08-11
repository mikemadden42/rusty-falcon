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
pub struct FalconxReportV1 {
    #[serde(rename = "cid", skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    #[serde(rename = "created_timestamp", skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "intel", skip_serializing_if = "Option::is_none")]
    pub intel: Option<Vec<crate::models::FalconxIntelReportV1>>,
    #[serde(
        rename = "ioc_report_broad_csv_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_broad_csv_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_broad_json_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_broad_json_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_broad_maec_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_broad_maec_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_broad_stix_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_broad_stix_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_strict_csv_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_strict_csv_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_strict_json_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_strict_json_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_strict_maec_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_strict_maec_artifact_id: Option<String>,
    #[serde(
        rename = "ioc_report_strict_stix_artifact_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub ioc_report_strict_stix_artifact_id: Option<String>,
    #[serde(rename = "malquery", skip_serializing_if = "Option::is_none")]
    pub malquery: Option<Vec<crate::models::FalconxMalqueryReportV1>>,
    #[serde(rename = "origin", skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(rename = "sandbox", skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<Vec<crate::models::FalconxSandboxReportV1>>,
    #[serde(rename = "tags", skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "threat_graph", skip_serializing_if = "Option::is_none")]
    pub threat_graph: Option<Box<crate::models::FalconxThreatGraphReportV1>>,
    #[serde(rename = "user_id", skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(rename = "user_name", skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(rename = "user_tags", skip_serializing_if = "Option::is_none")]
    pub user_tags: Option<Vec<String>>,
    #[serde(rename = "user_uuid", skip_serializing_if = "Option::is_none")]
    pub user_uuid: Option<String>,
    #[serde(rename = "verdict", skip_serializing_if = "Option::is_none")]
    pub verdict: Option<String>,
}

impl FalconxReportV1 {
    pub fn new() -> FalconxReportV1 {
        FalconxReportV1 {
            cid: None,
            created_timestamp: None,
            id: None,
            intel: None,
            ioc_report_broad_csv_artifact_id: None,
            ioc_report_broad_json_artifact_id: None,
            ioc_report_broad_maec_artifact_id: None,
            ioc_report_broad_stix_artifact_id: None,
            ioc_report_strict_csv_artifact_id: None,
            ioc_report_strict_json_artifact_id: None,
            ioc_report_strict_maec_artifact_id: None,
            ioc_report_strict_stix_artifact_id: None,
            malquery: None,
            origin: None,
            sandbox: None,
            tags: None,
            threat_graph: None,
            user_id: None,
            user_name: None,
            user_tags: None,
            user_uuid: None,
            verdict: None,
        }
    }
}
