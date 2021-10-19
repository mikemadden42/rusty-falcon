/*
 * CrowdStrike API Specification
 *
 * Use this API specification as a reference for the API endpoints you can use to interact with your Falcon environment. These endpoints support authentication via OAuth2 and interact with detections and network containment. For detailed usage guides and more information about API endpoints that don't yet support OAuth2, see our [documentation inside the Falcon console](https://falcon.crowdstrike.com/support/documentation). To use the APIs described below, combine the base URL with the path shown for each API endpoint. For commercial cloud customers, your base URL is `https://api.crowdstrike.com`. Each API endpoint requires authorization via an OAuth2 token. Your first API request should retrieve an OAuth2 token using the `oauth2/token` endpoint, such as `https://api.crowdstrike.com/oauth2/token`. For subsequent requests, include the OAuth2 token in an HTTP authorization header. Tokens expire after 30 minutes, after which you should make a new token request to continue making API requests.
 *
 * The version of the OpenAPI document: 2021-10-05T19:33:53Z
 * 
 * Generated by: https://openapi-generator.tech
 */




#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
pub struct DomainNotificationDetailsV1 {
    /// The raw intelligence item author username
    #[serde(rename = "author", skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    /// Highlighted content based on the rule that generated the notifications. Highlights are surrounded with a <cs-highlight> tag
    #[serde(rename = "content")]
    pub content: String,
    /// The date when the raw intelligence item was created
    #[serde(rename = "created_date")]
    pub created_date: String,
    /// The raw intelligence item labels. These contain hints around what is actually included in the item (malware, IPs, emails, etc).
    #[serde(rename = "labels", skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,
    /// The raw intelligence item language
    #[serde(rename = "language", skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// The site where the raw intelligence item was found
    #[serde(rename = "site", skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    /// The raw intelligence item title
    #[serde(rename = "title", skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The ID of the notifications
    #[serde(rename = "type")]
    pub _type: String,
    /// The date when the raw intelligence item was updated
    #[serde(rename = "updated_date")]
    pub updated_date: String,
    /// The raw intelligence item URL
    #[serde(rename = "url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl DomainNotificationDetailsV1 {
    pub fn new(content: String, created_date: String, _type: String, updated_date: String) -> DomainNotificationDetailsV1 {
        DomainNotificationDetailsV1 {
            author: None,
            content,
            created_date,
            labels: None,
            language: None,
            site: None,
            title: None,
            _type,
            updated_date,
            url: None,
        }
    }
}


