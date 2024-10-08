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
pub struct RulegroupsPeriodRule {
    #[serde(rename = "content_files", skip_serializing_if = "Option::is_none")]
    pub content_files: Option<Vec<String>>,
    #[serde(
        rename = "content_registry_values",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_registry_values: Option<Vec<String>>,
    #[serde(rename = "created_timestamp", skip_serializing_if = "Option::is_none")]
    pub created_timestamp: Option<String>,
    #[serde(rename = "depth")]
    pub depth: String,
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(
        rename = "enable_content_capture",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable_content_capture: Option<bool>,
    #[serde(
        rename = "enable_hash_capture",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable_hash_capture: Option<bool>,
    #[serde(rename = "exclude", skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    #[serde(rename = "exclude_processes", skip_serializing_if = "Option::is_none")]
    pub exclude_processes: Option<String>,
    #[serde(rename = "exclude_users", skip_serializing_if = "Option::is_none")]
    pub exclude_users: Option<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "include")]
    pub include: String,
    #[serde(rename = "include_processes", skip_serializing_if = "Option::is_none")]
    pub include_processes: Option<String>,
    #[serde(rename = "include_users", skip_serializing_if = "Option::is_none")]
    pub include_users: Option<String>,
    #[serde(rename = "modified_timestamp", skip_serializing_if = "Option::is_none")]
    pub modified_timestamp: Option<String>,
    #[serde(rename = "path")]
    pub path: String,
    #[serde(rename = "precedence", skip_serializing_if = "Option::is_none")]
    pub precedence: Option<i32>,
    #[serde(rename = "rule_group_id")]
    pub rule_group_id: String,
    #[serde(rename = "severity")]
    pub severity: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(
        rename = "watch_attributes_directory_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_attributes_directory_changes: Option<bool>,
    #[serde(
        rename = "watch_attributes_file_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_attributes_file_changes: Option<bool>,
    #[serde(
        rename = "watch_create_directory_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_create_directory_changes: Option<bool>,
    #[serde(
        rename = "watch_create_file_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_create_file_changes: Option<bool>,
    #[serde(
        rename = "watch_create_key_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_create_key_changes: Option<bool>,
    #[serde(
        rename = "watch_delete_directory_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_delete_directory_changes: Option<bool>,
    #[serde(
        rename = "watch_delete_file_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_delete_file_changes: Option<bool>,
    #[serde(
        rename = "watch_delete_key_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_delete_key_changes: Option<bool>,
    #[serde(
        rename = "watch_delete_value_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_delete_value_changes: Option<bool>,
    #[serde(
        rename = "watch_permissions_directory_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_permissions_directory_changes: Option<bool>,
    #[serde(
        rename = "watch_permissions_file_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_permissions_file_changes: Option<bool>,
    #[serde(
        rename = "watch_permissions_key_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_permissions_key_changes: Option<bool>,
    #[serde(
        rename = "watch_rename_directory_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_rename_directory_changes: Option<bool>,
    #[serde(
        rename = "watch_rename_file_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_rename_file_changes: Option<bool>,
    #[serde(
        rename = "watch_rename_key_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_rename_key_changes: Option<bool>,
    #[serde(
        rename = "watch_set_value_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_set_value_changes: Option<bool>,
    #[serde(
        rename = "watch_write_file_changes",
        skip_serializing_if = "Option::is_none"
    )]
    pub watch_write_file_changes: Option<bool>,
}

impl RulegroupsPeriodRule {
    pub fn new(
        depth: String,
        id: String,
        include: String,
        path: String,
        rule_group_id: String,
        severity: String,
        r#type: String,
    ) -> RulegroupsPeriodRule {
        RulegroupsPeriodRule {
            content_files: None,
            content_registry_values: None,
            created_timestamp: None,
            depth,
            description: None,
            enable_content_capture: None,
            enable_hash_capture: None,
            exclude: None,
            exclude_processes: None,
            exclude_users: None,
            id,
            include,
            include_processes: None,
            include_users: None,
            modified_timestamp: None,
            path,
            precedence: None,
            rule_group_id,
            severity,
            r#type,
            watch_attributes_directory_changes: None,
            watch_attributes_file_changes: None,
            watch_create_directory_changes: None,
            watch_create_file_changes: None,
            watch_create_key_changes: None,
            watch_delete_directory_changes: None,
            watch_delete_file_changes: None,
            watch_delete_key_changes: None,
            watch_delete_value_changes: None,
            watch_permissions_directory_changes: None,
            watch_permissions_file_changes: None,
            watch_permissions_key_changes: None,
            watch_rename_directory_changes: None,
            watch_rename_file_changes: None,
            watch_rename_key_changes: None,
            watch_set_value_changes: None,
            watch_write_file_changes: None,
        }
    }
}
