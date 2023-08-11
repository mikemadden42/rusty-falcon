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
pub struct DomainDdosTargetDetails {
    /// The autonomous system number of the target
    #[serde(rename = "asn")]
    pub asn: i32,
    /// The autonomous system name of the target
    #[serde(rename = "asn_name")]
    pub asn_name: String,
    /// The CIDR of the IP address
    #[serde(rename = "cidr")]
    pub cidr: String,
    /// The target's city
    #[serde(rename = "city")]
    pub city: String,
    /// The name of the company who has registered the IP address
    #[serde(rename = "company_name")]
    pub company_name: String,
    /// The connection type of the target
    #[serde(rename = "connection_type")]
    pub connection_type: String,
    /// The target's country
    #[serde(rename = "country")]
    pub country: String,
    #[serde(rename = "country_code")]
    pub country_code: String,
    /// The passive DNS of the target
    #[serde(rename = "pdns")]
    pub pdns: Vec<String>,
    /// The reverse DNS hostname of the target's IP address
    #[serde(rename = "rdns")]
    pub rdns: String,
}

impl DomainDdosTargetDetails {
    pub fn new(
        asn: i32,
        asn_name: String,
        cidr: String,
        city: String,
        company_name: String,
        connection_type: String,
        country: String,
        country_code: String,
        pdns: Vec<String>,
        rdns: String,
    ) -> DomainDdosTargetDetails {
        DomainDdosTargetDetails {
            asn,
            asn_name,
            cidr,
            city,
            company_name,
            connection_type,
            country,
            country_code,
            pdns,
            rdns,
        }
    }
}
