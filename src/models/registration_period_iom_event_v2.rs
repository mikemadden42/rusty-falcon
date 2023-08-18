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
pub struct RegistrationPeriodIomEventV2 {
    #[serde(rename = "account_id")]
    pub account_id: String,
    #[serde(rename = "account_name")]
    pub account_name: String,
    #[serde(rename = "agent_id", skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "azure_tenant_id", skip_serializing_if = "Option::is_none")]
    pub azure_tenant_id: Option<String>,
    #[serde(rename = "cid")]
    pub cid: String,
    #[serde(rename = "cloud_labels", skip_serializing_if = "Option::is_none")]
    pub cloud_labels: Option<Vec<crate::models::ClassificationPeriodLabel>>,
    #[serde(rename = "cloud_provider")]
    pub cloud_provider: String,
    #[serde(rename = "cloud_scopes", skip_serializing_if = "Option::is_none")]
    pub cloud_scopes: Option<Vec<crate::models::DomainPeriodCloudScope>>,
    #[serde(rename = "custom_policy_id", skip_serializing_if = "Option::is_none")]
    pub custom_policy_id: Option<i32>,
    #[serde(rename = "finding")]
    pub finding: serde_json::Value,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "is_managed", skip_serializing_if = "Option::is_none")]
    pub is_managed: Option<bool>,
    #[serde(rename = "policy_id", skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<i32>,
    #[serde(rename = "policy_statement")]
    pub policy_statement: String,
    #[serde(rename = "policy_type", skip_serializing_if = "Option::is_none")]
    pub policy_type: Option<String>,
    #[serde(rename = "region")]
    pub region: String,
    #[serde(rename = "report_date_time")]
    pub report_date_time: String,
    #[serde(rename = "resource_attributes")]
    pub resource_attributes: serde_json::Value,
    #[serde(rename = "resource_create_time")]
    pub resource_create_time: String,
    #[serde(rename = "resource_id")]
    pub resource_id: String,
    #[serde(rename = "resource_id_type")]
    pub resource_id_type: String,
    #[serde(rename = "resource_url")]
    pub resource_url: String,
    #[serde(rename = "resource_uuid")]
    pub resource_uuid: String,
    #[serde(rename = "scan_id", skip_serializing_if = "Option::is_none")]
    pub scan_id: Option<String>,
    #[serde(rename = "scan_time")]
    pub scan_time: String,
    #[serde(rename = "service")]
    pub service: String,
    #[serde(rename = "severity")]
    pub severity: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "tags")]
    pub tags: ::std::collections::HashMap<String, String>,
    #[serde(rename = "vm_id", skip_serializing_if = "Option::is_none")]
    pub vm_id: Option<String>,
}

impl RegistrationPeriodIomEventV2 {
    pub fn new(
        account_id: String,
        account_name: String,
        cid: String,
        cloud_provider: String,
        finding: serde_json::Value,
        id: String,
        policy_statement: String,
        region: String,
        report_date_time: String,
        resource_attributes: serde_json::Value,
        resource_create_time: String,
        resource_id: String,
        resource_id_type: String,
        resource_url: String,
        resource_uuid: String,
        scan_time: String,
        service: String,
        severity: String,
        status: String,
        tags: ::std::collections::HashMap<String, String>,
    ) -> RegistrationPeriodIomEventV2 {
        RegistrationPeriodIomEventV2 {
            account_id,
            account_name,
            agent_id: None,
            azure_tenant_id: None,
            cid,
            cloud_labels: None,
            cloud_provider,
            cloud_scopes: None,
            custom_policy_id: None,
            finding,
            id,
            is_managed: None,
            policy_id: None,
            policy_statement,
            policy_type: None,
            region,
            report_date_time,
            resource_attributes,
            resource_create_time,
            resource_id,
            resource_id_type,
            resource_url,
            resource_uuid,
            scan_id: None,
            scan_time,
            service,
            severity,
            status,
            tags,
            vm_id: None,
        }
    }
}