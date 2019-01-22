pub mod consts;
pub mod protos;

extern crate base64;
extern crate byteorder;
extern crate curl;
extern crate hex;
extern crate openssl;
extern crate protobuf;

#[macro_use]
extern crate serde_derive;

extern crate serde;
pub extern crate serde_json;

use std::collections::HashMap;
use std::error::Error;

pub use curl::easy::{Easy, List};
pub use protobuf::Message;

use protos::googleplay::{
    BulkDetailsRequest, BulkDetailsResponse, DetailsResponse, ResponseWrapper,
};

/// Play Store API endpoints supported
#[derive(Debug)]
pub enum Endpoint {
    Details,
    BulkDetails,
}

impl Endpoint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Endpoint::Details => "details",
            Endpoint::BulkDetails => "bulkDetails",
        }
    }
}

/// Play Store bulk package detail request.
pub fn bulk_details(
    pkg_names: Vec<String>,
    token: &str,
    android_id: &str,
) -> Result<Option<BulkDetailsResponse>, Box<Error>> {
    let mut req = BulkDetailsRequest::new();
    req.docid = pkg_names.into();
    req.includeDetails = Some(true);
    req.includeChildDocs = Some(false);

    let bytes = req.write_to_bytes()?;

    let resp = execute_request("bulkDetails", None, Some(&bytes), android_id, token)?;
    if let Some(payload) = resp.payload.into_option() {
        Ok(payload.bulkDetailsResponse.into_option())
    } else {
        Ok(None)
    }
}

/// Play Store package detail request (provides more detail than bulk requests).
pub fn details(
    pkg_name: &str,
    token: &str,
    android_id: &str,
) -> Result<Option<DetailsResponse>, Box<Error>> {
    let req: HashMap<&str, &str> = [("doc", pkg_name)].iter().cloned().collect();

    let resp = execute_request("details", Some(req), None, android_id, token)?;
    if let Some(payload) = resp.payload.into_option() {
        Ok(payload.detailsResponse.into_option())
    } else {
        Ok(None)
    }
}

/// Lower level Play Store request, used by APIs but exposed for specialized
/// requests. Returns a `ResponseWrapper` which depending on the request
/// populates different fields/values.
pub fn execute_request(
    endpoint: &str,
    query: Option<HashMap<&str, &str>>,
    msg: Option<&[u8]>,
    android_id: &str,
    token: &str,
) -> Result<ResponseWrapper, Box<Error>> {
    let mut easy = Easy::new();

    let url = format!("{}/{}", "https://android.clients.google.com/fdfe", endpoint);

    if let Some(query) = query {
        easy.url_query(&url, query)?;
    } else {
        easy.url(&url)?;
    }

    let mut list = List::new();
    list.append("Accept-Language: en_US")?;
    list.append(&format!("Authorization: GoogleLogin auth={}", token))?;
    list.append("X-DFE-Enabled-Experiments: cl:billing.select_add_instrument_by_default")?;
    list.append("X-DFE-Unsupported-Experiments: nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes").unwrap();
    list.append(&format!("X-DFE-Device-Id: {}", android_id))?;
    list.append(&format!("X-DFE-Client-Id: am-android-google"))?;
    list.append("X-DFE-SmallestScreenWidthDp: 320")?;
    list.append("X-DFE-Filter-Level: 3")?;
    list.append("X-DFE-No-Prefetch: true")?;
    list.append("Content-Type: application/x-protobuf")?;
    easy.http_headers(list)?;

    let config = BuildConfiguration {
        ..Default::default()
    };
    easy.useragent(&config.user_agent())?;

    if let Some(msg) = msg {
        easy.post_fields_copy(&msg)?;
    }

    let mut buf = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            buf.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }

    let mut resp = ResponseWrapper::new();
    resp.merge_from_bytes(&buf)?;
    Ok(resp)
}

#[derive(Debug)]
pub struct PubKey {
    pub modulus: Vec<u8>,
    pub exp: Vec<u8>,
}

#[derive(Default)]
pub struct Gpapi {
    pub username: String,
    pub password: String,
    pub android_id: String,
    pub token: String,
}

impl Gpapi {
    pub fn new<S: Into<String>>(username: S, password: S, android_id: S) -> Self {
        Gpapi {
            username: username.into(),
            password: password.into(),
            android_id: android_id.into(),
            ..Default::default()
        }
    }

    pub fn auth_user_password(&mut self) -> Result<(), Box<Error>> {
        match self {
            Gpapi {
                username: ref u,
                password: ref p,
                android_id: ref a,
                ..
            } => {
                let form = login(u, p, a)?;
                if let Some(token) = form.get("auth") {
                    self.token = token.to_string();
                    Ok(())
                } else {
                    unimplemented!()
                }
            }
        }
    }
}

/// Handles logging into Google Play Store, retrieving a set of tokens from
/// the server that can be used for future requests.
/// The `android_id` is obtained by retrieving your
/// [GSF id](https://blog.onyxbits.de/what-exactly-is-a-gsf-id-where-do-i-get-it-from-and-why-should-i-care-2-12/).
/// You can also get your **GSF ID**  using this following [device id app](https://play.google.com/store/apps/details?id=com.evozi.deviceid&hl=en)
/// Note that you don't want the Android ID here, but the GSF id.
/// We call it the `android_id` internally for legacy reasons.
pub fn login(
    username: &str,
    password: &str,
    android_id: &str,
) -> Result<HashMap<String, String>, Box<Error>> {
    use consts::defaults::DEFAULT_LOGIN_URL;

    let req = build_login_request(username, password, android_id);

    let mut easy = curl::easy::Easy::new();
    easy.url(DEFAULT_LOGIN_URL)?;
    easy.useragent(consts::defaults::DEFAULT_AUTH_USER_AGENT)?;
    easy.post(true)?;
    let form_body = req.form_post();
    easy.post_fields_copy(form_body.as_bytes())?;

    let mut buf = Vec::new();
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            buf.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }

    let reply = parse_form_reply(&std::str::from_utf8(&buf).unwrap());
    Ok(dbg!(reply))
}

pub fn parse_form_reply(data: &str) -> HashMap<String, String> {
    let mut form_resp = HashMap::new();
    let lines: Vec<&str> = data.split_terminator('\n').collect();
    for line in lines.iter() {
        let kv: Vec<&str> = line.split_terminator('=').collect();
        form_resp.insert(String::from(kv[0]).to_lowercase(), String::from(kv[1]));
    }
    form_resp
}

/// Handles encrypting your login/password using Google's public key
/// Produces something of the format:
/// |00|4 bytes of sha1(publicKey)|rsaEncrypt(publicKeyPem, "login\x00password")|
pub fn encrypt_login(login: &str, password: &str) -> Option<Vec<u8>> {
    let raw = base64::decode(consts::GOOGLE_PUB_KEY_B64).unwrap();
    if let Ok(Some(pubkey)) = extract_pubkey(&raw) {
        let rsa = build_openssl_rsa(&pubkey);

        let data = format!("{login}\x00{password}", login = login, password = password);
        let mut to = vec![0u8; rsa.size() as usize];
        let padding = openssl::rsa::Padding::PKCS1_OAEP;

        if let Ok(_sz) = rsa.public_encrypt(data.as_bytes(), &mut to, padding) {
            let sha1 = openssl::sha::sha1(&raw);
            let mut res = vec![];
            res.push(0x00);
            res.extend(&sha1[0..4]);
            res.extend(&to);
            Some(res)
        } else {
            None
        }
    } else {
        None
    }
}

///
/// Base64 encode w/ URL safe characters.
///
pub fn base64_urlsafe(input: &[u8]) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

///
/// Gen up an `openssl::rsa::Rsa` from a `PubKey`.
///
pub fn build_openssl_rsa(p: &PubKey) -> openssl::rsa::Rsa<openssl::pkey::Public> {
    use openssl::bn::BigNum;
    use openssl::rsa::Rsa;

    let modulus = BigNum::from_hex_str(&hex::encode(&p.modulus)).unwrap();
    let exp = BigNum::from_hex_str(&hex::encode(&p.exp)).unwrap();
    let rsa = Rsa::from_public_components(modulus, exp).unwrap();

    rsa
}

///
/// Extract public key (PEM) from a raw buffer.
///
fn extract_pubkey(buf: &[u8]) -> Result<Option<PubKey>, Box<Error>> {
    use byteorder::{NetworkEndian, ReadBytesExt};
    use std::io::{Cursor, Read};
    let mut cur = Cursor::new(&buf);

    let sz = cur.read_u32::<NetworkEndian>()?;
    let mut modulus = vec![0u8; sz as usize];
    cur.read_exact(&mut modulus)?;

    let sz = cur.read_u32::<NetworkEndian>()?;
    let mut exp = vec![0u8; sz as usize];
    cur.read_exact(&mut exp)?;

    Ok(Some(PubKey { modulus, exp }))
}

#[derive(Debug, Clone)]
pub struct LoginRequest {
    email: String,
    encrypted_password: String,
    service: String,
    account_type: String,
    has_permission: String,
    source: String,
    android_id: String,
    app: String,
    device_country: String,
    operator_country: String,
    lang: String,
    sdk_version: String,
    build_config: Option<BuildConfiguration>,
}

impl LoginRequest {
    pub fn form_post(&self) -> String {
        format!("Email={}&EncryptedPasswd={}&service={}&accountType={}&has_permission={}&source={}&androidId={}&app={}&device_country={}&operatorCountry={}&lang={}&sdk_version={}",
         self.email, self.encrypted_password, self.service, self.account_type, self.has_permission, self.source, self.android_id, self.app,self.device_country, self.operator_country, self.lang, self.sdk_version)
    }
}

#[derive(Debug, Clone)]
pub struct BuildConfiguration {
    pub finsky_agent: String,
    pub finsky_version: String,
    pub api: String,
    pub version_code: String,
    pub sdk: String,
    pub device: String,
    pub hardware: String,
    pub product: String,
    pub platform_version_release: String,
    pub model: String,
    pub build_id: String,
    pub is_wide_screen: String,
}

impl BuildConfiguration {
    pub fn user_agent(&self) -> String {
        format!("{}/{} (api={},versionCode={},sdk={},device={},hardware={},product={},platformVersionRelease={},model={},buildId={},isWideScreen={})", 
          self.finsky_agent, self.finsky_version, self.api, self.version_code, self.sdk,
          self.device, self.hardware, self.product,
          self.platform_version_release, self.model, self.build_id,
          self.is_wide_screen
        )
    }
}

impl Default for BuildConfiguration {
    fn default() -> BuildConfiguration {
        use consts::defaults::api_user_agent::{
            DEFAULT_API, DEFAULT_BUILD_ID, DEFAULT_DEVICE, DEFAULT_HARDWARE,
            DEFAULT_IS_WIDE_SCREEN, DEFAULT_MODEL, DEFAULT_PLATFORM_VERSION_RELEASE,
            DEFAULT_PRODUCT, DEFAULT_SDK, DEFAULT_VERSION_CODE,
        };
        use consts::defaults::{DEFAULT_FINSKY_AGENT, DEFAULT_FINSKY_VERSION};

        BuildConfiguration {
            finsky_agent: DEFAULT_FINSKY_AGENT.to_string(),
            finsky_version: DEFAULT_FINSKY_VERSION.to_string(),
            api: DEFAULT_API.to_string(),
            version_code: DEFAULT_VERSION_CODE.to_string(),
            sdk: DEFAULT_SDK.to_string(),
            device: DEFAULT_DEVICE.to_string(),
            hardware: DEFAULT_HARDWARE.to_string(),
            product: DEFAULT_PRODUCT.to_string(),
            platform_version_release: DEFAULT_PLATFORM_VERSION_RELEASE.to_string(),
            model: DEFAULT_MODEL.to_string(),
            build_id: DEFAULT_BUILD_ID.to_string(),
            is_wide_screen: DEFAULT_IS_WIDE_SCREEN.to_string(),
        }
    }
}

impl Default for LoginRequest {
    fn default() -> Self {
        LoginRequest {
            email: String::from(""),
            encrypted_password: String::from(""),
            service: String::from(consts::defaults::DEFAULT_SERVICE),
            account_type: String::from(consts::defaults::DEFAULT_ACCOUNT_TYPE),
            has_permission: String::from("1"),
            source: String::from("android"),
            android_id: String::from(""),
            app: String::from(consts::defaults::DEFAULT_ANDROID_VENDING),
            device_country: String::from(consts::defaults::DEFAULT_DEVICE_COUNTRY),
            operator_country: String::from(consts::defaults::DEFAULT_COUNTRY_CODE),
            lang: String::from(consts::defaults::DEFAULT_LANGUAGE),
            sdk_version: String::from(consts::defaults::DEFAULT_SDK_VERSION),
            build_config: None,
        }
    }
}

pub fn build_login_request(username: &str, password: &str, android_id: &str) -> LoginRequest {
    let login = encrypt_login(username, password).unwrap();
    let encrypted_password = base64_urlsafe(&login);
    let build_config = BuildConfiguration {
        ..Default::default()
    };
    LoginRequest {
        email: String::from(username),
        encrypted_password,
        android_id: String::from(android_id),
        build_config: Some(build_config),
        ..Default::default()
    }
}

/// A trait that provides a convenience method for using URL-encoded query paramaters in a URL with `curl::Easy`
pub trait QueryParams {
    fn url_query(&mut self, url: &str, query: HashMap<&str, &str>) -> Result<(), curl::Error>;
}

impl QueryParams for Easy {
    /// Convenience method to set the `url` with query parameters.
    fn url_query(&mut self, url: &str, query: HashMap<&str, &str>) -> Result<(), curl::Error> {
        let mut res = vec![];
        for (key, val) in query.iter() {
            res.push(self.url_encode(format!("{}={}", key, val).as_bytes()));
        }
        self.url(&format!("{}?{}", url, res.join("&")))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn login() {
        let enc = ::encrypt_login("foo", "bar").unwrap();
        println!("encrypted: {:?}", base64::encode(&enc));
        println!("base64_urlsafe: {:?}", ::base64_urlsafe(&enc));
    }

    #[test]
    fn parse_form() {
        let form_reply = "FOO=BAR\nbaz=qux";
        let x = ::parse_form_reply(&form_reply);
        println!("form (parsed): {:?}", x);
    }

    #[test]
    fn foobar() {
        assert!(1 == 1);
    }

    mod gpapi {
        #[test]
        fn test_protobuf() {
            use protos::googleplay::BulkDetailsRequest;
            let mut x = BulkDetailsRequest::new();
            x.docid = vec!["test".to_string()].into();
            x.includeDetails = true;
            x.includeChildDocs = true;
        }
    }
}
