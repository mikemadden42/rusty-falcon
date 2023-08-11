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
pub struct DomainIncident {
    #[serde(rename = "assigned_to", skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    #[serde(rename = "assigned_to_name", skip_serializing_if = "Option::is_none")]
    pub assigned_to_name: Option<String>,
    #[serde(rename = "cid")]
    pub cid: String,
    #[serde(rename = "created")]
    pub created: String,
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "end")]
    pub end: String,
    #[serde(rename = "events_histogram", skip_serializing_if = "Option::is_none")]
    pub events_histogram: Option<Vec<crate::models::DomainEventHistogram>>,
    #[serde(rename = "fine_score")]
    pub fine_score: i32,
    #[serde(rename = "host_ids")]
    pub host_ids: Vec<String>,
    #[serde(rename = "hosts", skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<crate::models::DetectsDeviceDetailIndexed>>,
    #[serde(rename = "incident_id")]
    pub incident_id: String,
    #[serde(rename = "incident_type", skip_serializing_if = "Option::is_none")]
    pub incident_type: Option<i32>,
    #[serde(rename = "lm_host_ids", skip_serializing_if = "Option::is_none")]
    pub lm_host_ids: Option<Vec<String>>,
    #[serde(rename = "lm_hosts_capped", skip_serializing_if = "Option::is_none")]
    pub lm_hosts_capped: Option<bool>,
    #[serde(rename = "modified_timestamp", skip_serializing_if = "Option::is_none")]
    pub modified_timestamp: Option<String>,
    #[serde(rename = "name", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "objectives", skip_serializing_if = "Option::is_none")]
    pub objectives: Option<Vec<String>>,
    #[serde(rename = "start")]
    pub start: String,
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<i32>,
    #[serde(rename = "tactics", skip_serializing_if = "Option::is_none")]
    pub tactics: Option<Vec<String>>,
    #[serde(rename = "tags", skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "techniques", skip_serializing_if = "Option::is_none")]
    pub techniques: Option<Vec<String>>,
    #[serde(rename = "users", skip_serializing_if = "Option::is_none")]
    pub users: Option<Vec<String>>,
    #[serde(rename = "visibility", skip_serializing_if = "Option::is_none")]
    pub visibility: Option<i32>,
}

impl DomainIncident {
    pub fn new(
        cid: String,
        created: String,
        end: String,
        fine_score: i32,
        host_ids: Vec<String>,
        incident_id: String,
        start: String,
        state: String,
    ) -> DomainIncident {
        DomainIncident {
            assigned_to: None,
            assigned_to_name: None,
            cid,
            created,
            description: None,
            end,
            events_histogram: None,
            fine_score,
            host_ids,
            hosts: None,
            incident_id,
            incident_type: None,
            lm_host_ids: None,
            lm_hosts_capped: None,
            modified_timestamp: None,
            name: None,
            objectives: None,
            start,
            state,
            status: None,
            tactics: None,
            tags: None,
            techniques: None,
            users: None,
            visibility: None,
        }
    }
}
