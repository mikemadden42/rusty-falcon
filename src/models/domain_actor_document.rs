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
pub struct DomainActorDocument {
    #[serde(rename = "active")]
    pub active: bool,
    #[serde(rename = "actor_type", skip_serializing_if = "Option::is_none")]
    pub actor_type: Option<String>,
    #[serde(rename = "capability", skip_serializing_if = "Option::is_none")]
    pub capability: Option<Box<crate::models::DomainEntity>>,
    #[serde(rename = "created_date")]
    pub created_date: i64,
    #[serde(rename = "description", skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "ecrime_kill_chain", skip_serializing_if = "Option::is_none")]
    pub ecrime_kill_chain: Option<Box<crate::models::DomainECrimeKillChain>>,
    #[serde(rename = "entitlements", skip_serializing_if = "Option::is_none")]
    pub entitlements: Option<Vec<crate::models::DomainEntity>>,
    #[serde(rename = "first_activity_date")]
    pub first_activity_date: i64,
    #[serde(rename = "group", skip_serializing_if = "Option::is_none")]
    pub group: Option<Box<crate::models::DomainEntity>>,
    #[serde(rename = "id")]
    pub id: i64,
    #[serde(rename = "image", skip_serializing_if = "Option::is_none")]
    pub image: Option<Box<crate::models::DomainImage>>,
    #[serde(rename = "kill_chain", skip_serializing_if = "Option::is_none")]
    pub kill_chain: Option<Box<crate::models::DomainKillChain>>,
    #[serde(rename = "known_as")]
    pub known_as: String,
    #[serde(rename = "last_activity_date")]
    pub last_activity_date: i64,
    #[serde(rename = "last_modified_date")]
    pub last_modified_date: i64,
    #[serde(rename = "motivations")]
    pub motivations: Vec<crate::models::DomainEntity>,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "notify_users")]
    pub notify_users: bool,
    #[serde(rename = "origins")]
    pub origins: Vec<crate::models::DomainEntity>,
    #[serde(rename = "region", skip_serializing_if = "Option::is_none")]
    pub region: Option<Box<crate::models::DomainEntity>>,
    #[serde(rename = "rich_text_description", skip_serializing_if = "Option::is_none")]
    pub rich_text_description: Option<String>,
    #[serde(rename = "short_description")]
    pub short_description: String,
    #[serde(rename = "slug")]
    pub slug: String,
    #[serde(rename = "target_countries")]
    pub target_countries: Vec<crate::models::DomainEntity>,
    #[serde(rename = "target_industries")]
    pub target_industries: Vec<crate::models::DomainEntity>,
    #[serde(rename = "thumbnail", skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<Box<crate::models::DomainImage>>,
    #[serde(rename = "url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl DomainActorDocument {
    pub fn new(active: bool, created_date: i64, first_activity_date: i64, id: i64, known_as: String, last_activity_date: i64, last_modified_date: i64, motivations: Vec<crate::models::DomainEntity>, name: String, notify_users: bool, origins: Vec<crate::models::DomainEntity>, short_description: String, slug: String, target_countries: Vec<crate::models::DomainEntity>, target_industries: Vec<crate::models::DomainEntity>) -> DomainActorDocument {
        DomainActorDocument {
            active,
            actor_type: None,
            capability: None,
            created_date,
            description: None,
            ecrime_kill_chain: None,
            entitlements: None,
            first_activity_date,
            group: None,
            id,
            image: None,
            kill_chain: None,
            known_as,
            last_activity_date,
            last_modified_date,
            motivations,
            name,
            notify_users,
            origins,
            region: None,
            rich_text_description: None,
            short_description,
            slug,
            target_countries,
            target_industries,
            thumbnail: None,
            url: None,
        }
    }
}


