pub mod apk;
pub mod consts;
pub mod protos;

extern crate base64;
extern crate byteorder;
extern crate hex;
extern crate openssl;
extern crate protobuf;
extern crate reqwest;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

use protos::googleplay::{
    BulkDetailsRequest, BulkDetailsResponse, BuyResponse, DeliveryResponse, DetailsResponse,
    ResponseWrapper,
};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::Url;
use std::collections::HashMap;
use std::error::Error;

pub use protobuf::{Message, SingularPtrField};

pub const STATUS_UNAVAIL: i32 = 2;
pub const STATUS_PURCHASE_REQD: i32 = 3;

#[derive(Debug)]
pub struct Gpapi {
    pub username: String,
    pub password: String,
    pub gsf_id: String,
    pub token: String,
    pub client: Box<reqwest::Client>,
}

impl Gpapi {
    pub fn new<S: Into<String>>(username: S, password: S, gsf_id: S) -> Self {
        Gpapi {
            username: username.into(),
            password: password.into(),
            gsf_id: gsf_id.into(),
            token: String::from(""),
            client: Box::new(reqwest::Client::new()),
        }
    }

    /// Handles logging into Google Play Store, retrieving a set of tokens from
    /// the server that can be used for future requests.
    /// The `gsf_id` is obtained by retrieving your
    /// [GSF id](https://blog.onyxbits.de/what-exactly-is-a-gsf-id-where-do-i-get-it-from-and-why-should-i-care-2-12/).
    /// You can also get your **GSF ID**  using this following [device id app](https://play.google.com/store/apps/details?id=com.evozi.deviceid&hl=en)
    /// Note that you don't want the Android ID here, but the GSF id.
    fn login(&self) -> Result<HashMap<String, String>, Box<Error>> {
        use consts::defaults::DEFAULT_LOGIN_URL;

        let login_req = ::build_login_request(&self.username, &self.password, &self.gsf_id);

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&consts::defaults::DEFAULT_AUTH_USER_AGENT)?,
        );
        headers.insert(
            reqwest::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
        );

        let form_body = login_req.form_post();
        let mut res = (*self.client)
            .post(DEFAULT_LOGIN_URL)
            .headers(headers)
            .body(form_body)
            .send()?;

        let mut buf = Vec::new();
        res.copy_to(&mut buf)?;
        let reply = parse_form_reply(&std::str::from_utf8(&buf).unwrap());
        Ok(reply)
    }

    /// Play Store package detail request (provides more detail than bulk requests).
    pub fn details(&self, pkg_name: &str) -> Result<Option<DetailsResponse>, Box<Error>> {
        let mut req = HashMap::new();

        req.insert("doc", pkg_name);

        let resp = self.execute_request_v2("details", Some(req), None, None)?;

        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.detailsResponse.into_option())
        } else {
            Ok(None)
        }
    }

    pub fn bulk_details(
        &self,
        pkg_names: &[&str],
    ) -> Result<Option<BulkDetailsResponse>, Box<Error>> {
        let mut req = BulkDetailsRequest::new();
        req.docid = pkg_names.into_iter().cloned().map(String::from).collect();
        req.includeDetails = Some(true);
        req.includeChildDocs = Some(false);

        let bytes = req.write_to_bytes()?;

        let resp = self.execute_request_v2(
            "bulkDetails",
            None,
            Some(&bytes),
            Some("application/x-protobuf"),
        )?;

        if let Some(payload) = resp.payload.into_option() {
            Ok(payload.bulkDetailsResponse.into_option())
        } else {
            Ok(None)
        }
    }

    pub fn get_download_url(&self, pkg_name: &str, vc: u64) -> Result<Option<String>, Box<Error>> {
        if let Ok(Some(ref app_delivery_resp)) = self.app_delivery_data(pkg_name, vc) {
            match app_delivery_resp {
                DeliveryResponse {
                    status: None,
                    appDeliveryData: app_delivery_data,
                    ..
                } => Ok(app_delivery_data.clone().unwrap().downloadUrl.into_option()),
                DeliveryResponse {
                    status: Some(STATUS_UNAVAIL),
                    ..
                } => Err(format!("can't locate {}", pkg_name).into()),
                DeliveryResponse {
                    status: Some(STATUS_PURCHASE_REQD),
                    ..
                } => match self.purchase(pkg_name, vc) {
                    Ok(Some(purchase_resp)) => Ok(purchase_resp
                        .purchaseStatusResponse
                        .unwrap_or_default()
                        .appDeliveryData
                        .unwrap_or_default()
                        .downloadUrl
                        .into_option()),
                    Err(err) => Err(format!("error purchasing {:?}", err).into()),
                    _ => unimplemented!(),
                },
                _ => {
                    dbg!(app_delivery_resp);
                    unimplemented!()
                }
            }
        } else {
            if let Ok(Some(purchase_resp)) = self.purchase(pkg_name, vc) {
                Ok(purchase_resp
                    .purchaseStatusResponse
                    .unwrap()
                    .appDeliveryData
                    .unwrap()
                    .downloadUrl
                    .into_option())
            } else {
                Err("didn't get purchase data".into())
            }
        }
    }

    pub fn app_delivery_data(
        &self,
        pkg_name: &str,
        vc: u64,
    ) -> Result<Option<DeliveryResponse>, Box<dyn Error>> {
        let vc = vc.to_string();

        let mut req = HashMap::new();

        req.insert("doc", pkg_name);
        req.insert("vc", &vc);
        req.insert("ot", "1");

        let delivery_resp = self.execute_request_v2("delivery", Some(req), None, None)?;

        // dbg!(&delivery_resp);

        if let Some(payload) = delivery_resp.payload.into_option() {
            Ok(payload.deliveryResponse.into_option())
        } else {
            Ok(None)
        }
    }

    pub fn purchase(&self, pkg_name: &str, vc: u64) -> Result<Option<BuyResponse>, Box<dyn Error>> {
        let vc = vc.to_string();
        let body = format!("ot=1&doc={}&vc={}", pkg_name, vc);
        let body_bytes = body.into_bytes();

        let resp = self.execute_request_v2("purchase", None, Some(&body_bytes), None)?;

        // dbg!(&resp);

        match resp {
            ResponseWrapper {
                commands, payload, ..
            } => match (commands.into_option(), payload.into_option()) {
                (_, Some(payload)) => Ok(payload.buyResponse.into_option()),
                (Some(commands), _) => Err(commands.displayErrorMessage.unwrap().into()),
                _ => unimplemented!(),
            }, // ResponseWrapper { commands: SingularPtrField<ServerCommands>::some(commands), .. } => Err(commands.displayErrorMessage)
        }
        // if let Some(payload) = resp.payload.into_option() {
        //     Ok(payload.buyResponse.into_option())
        // } else {
        //     Ok(None)
        // }
    }

    pub fn authenticate(&mut self) -> Result<(), Box<Error>> {
        let form = self.login()?;
        if let Some(token) = form.get("auth") {
            self.token = token.to_string();
            Ok(())
        } else {
            panic!("no GSF auth token");
        }
    }

    /// Lower level Play Store request, used by APIs but exposed for specialized
    /// requests. Returns a `ResponseWrapper` which depending on the request
    /// populates different fields/values.
    pub fn execute_request_v2(
        &self,
        endpoint: &str,
        query: Option<HashMap<&str, &str>>,
        msg: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Result<ResponseWrapper, Box<Error>> {
        let mut url = Url::parse(&format!(
            "{}/{}",
            "https://android.clients.google.com/fdfe", endpoint
        ))?;

        let config = BuildConfiguration {
            ..Default::default()
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_str(&config.user_agent())?,
        );
        headers.insert(
            reqwest::header::ACCEPT_LANGUAGE,
            HeaderValue::from_static("en_US"),
        );
        headers.insert(
            reqwest::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("GoogleLogin auth={}", self.token))?,
        );
        headers.insert(
            "X-DFE-Enabled-Experiments",
            HeaderValue::from_static("cl:billing.select_add_instrument_by_default"),
        );
        headers.insert("X-DFE-Unsupported-Experiments", HeaderValue::from_static("nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes"));
        headers.insert("X-DFE-Device-Id", HeaderValue::from_str(&self.gsf_id)?);
        headers.insert(
            "X-DFE-Client-Id",
            HeaderValue::from_static("am-android-google"),
        );
        headers.insert(
            "X-DFE-SmallestScreenWidthDp",
            HeaderValue::from_static("320"),
        );
        headers.insert("X-DFE-Filter-Level", HeaderValue::from_static("3"));
        headers.insert("X-DFE-No-Prefetch", HeaderValue::from_static("true"));

        if let Some(content_type) = content_type {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_str(content_type)?,
            );
        } else {
            headers.insert(
                reqwest::header::CONTENT_TYPE,
                HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
            );
        }

        if let Some(query) = query {
            let mut queries = url.query_pairs_mut();
            for (key, val) in query {
                queries.append_pair(key, val);
            }
        }

        let mut res = if let Some(msg) = msg {
            (*self.client)
                .post(url)
                .headers(headers)
                .body(msg.to_owned())
                .send()?
        } else {
            (*self.client).get(url).headers(headers).send()?
        };

        // dbg!(&res);

        let mut buf = Vec::new();
        res.copy_to(&mut buf)?;
        let mut resp = ResponseWrapper::new();
        resp.merge_from_bytes(&buf)?;
        Ok(resp)
    }
}

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

#[derive(Debug)]
pub struct PubKey {
    pub modulus: Vec<u8>,
    pub exp: Vec<u8>,
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
    gsf_id: String,
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
         self.email, self.encrypted_password, self.service, self.account_type, self.has_permission, self.source, self.gsf_id, self.app,self.device_country, self.operator_country, self.lang, self.sdk_version)
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
            gsf_id: String::from(""),
            app: String::from(consts::defaults::DEFAULT_ANDROID_VENDING),
            device_country: String::from(consts::defaults::DEFAULT_DEVICE_COUNTRY),
            operator_country: String::from(consts::defaults::DEFAULT_COUNTRY_CODE),
            lang: String::from(consts::defaults::DEFAULT_LANGUAGE),
            sdk_version: String::from(consts::defaults::DEFAULT_SDK_VERSION),
            build_config: None,
        }
    }
}

pub fn build_login_request(username: &str, password: &str, gsf_id: &str) -> LoginRequest {
    let login = encrypt_login(username, password).unwrap();
    let encrypted_password = base64_urlsafe(&login);
    let build_config = BuildConfiguration {
        ..Default::default()
    };
    LoginRequest {
        email: String::from(username),
        encrypted_password,
        gsf_id: String::from(gsf_id),
        build_config: Some(build_config),
        ..Default::default()
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

        use std::env;
        use Gpapi;

        #[test]
        fn create_gpapi() {
            match (
                env::var("GOOGLE_LOGIN"),
                env::var("GOOGLE_PASSWORD"),
                env::var("ANDROID_ID"),
            ) {
                (Ok(username), Ok(password), Ok(gsf_id)) => {
                    let mut api = Gpapi::new(username, password, gsf_id);
                    api.authenticate().ok();
                    dbg!(&api.token);
                    assert!(api.token != "");

                    let details = api.details("com.viber.voip").ok();
                    dbg!(details);

                    let pkg_names = ["com.viber.voip", "air.WatchESPN"];
                    let bulk_details = api.bulk_details(&pkg_names).ok();
                    dbg!(bulk_details);
                }
                _ => panic!("require login/password/gsf_id for test"),
            }
        }

        #[test]
        fn test_protobuf() {
            use protos::googleplay::BulkDetailsRequest;
            let mut x = BulkDetailsRequest::new();
            x.docid = vec!["test".to_string()].into();
            x.includeDetails = Some(true);
            x.includeChildDocs = Some(true);
        }
    }
}
// /// Play Store bulk package detail request.
// ///
// /// # Arguments
// /// `pkg_names`  - A list of up to 200 or so package names.
// /// `token`      - A valid GSF token for the request.
// /// `gsf_id` - A GSF device ID representing the device configuration profile.
// pub fn bulk_details(
//     pkg_names: &[&str],
//     token: &str,
//     gsf_id: &str,
// ) -> Result<Option<BulkDetailsResponse>, Box<Error>> {
//     let mut req = BulkDetailsRequest::new();
//     req.docid = pkg_names.into_iter().cloned().map(String::from).collect();
//     req.includeDetails = Some(true);
//     req.includeChildDocs = Some(false);

//     let bytes = req.write_to_bytes()?;

//     let resp = execute_request_v2(
//         "bulkDetails",
//         None,
//         Some(&bytes),
//         Some("application/x-protobuf"),
//         gsf_id,
//         token,
//     )?;

//     if let Some(payload) = resp.payload.into_option() {
//         Ok(payload.bulkDetailsResponse.into_option())
//     } else {
//         Ok(None)
//     }
// }

// /// Play Store package detail request (provides more detail than bulk requests).
// pub fn details(
//     pkg_name: &str,
//     token: &str,
//     gsf_id: &str,
// ) -> Result<Option<DetailsResponse>, Box<Error>> {
//     let mut req = HashMap::new();

//     req.insert("doc", pkg_name);

//     let resp = execute_request_v2("details", Some(req), None, None, gsf_id, token)?;

//     if let Some(payload) = resp.payload.into_option() {
//         Ok(payload.detailsResponse.into_option())
//     } else {
//         Ok(None)
//     }
// }

// pub fn app_delivery_data(
//     pkg_name: &str,
//     vc: u64,
//     token: &str,
//     gsf_id: &str,
// ) -> Result<Option<DeliveryResponse>, Box<dyn Error>> {
//     let vc = vc.to_string();

//     let mut req = HashMap::new();

//     req.insert("doc", pkg_name);
//     req.insert("vc", &vc);
//     req.insert("ot", "1");

//     let delivery_resp = execute_request_v2("delivery", Some(req), None, None, gsf_id, token)?;

//     // dbg!(&delivery_resp);

//     if let Some(payload) = delivery_resp.payload.into_option() {
//         Ok(payload.deliveryResponse.into_option())
//     } else {
//         Ok(None)
//     }
// }

// pub fn purchase(
//     pkg_name: &str,
//     vc: u64,
//     token: &str,
//     gsf_id: &str,
// ) -> Result<Option<BuyResponse>, Box<dyn Error>> {
//     let vc = vc.to_string();
//     let body = format!("ot=1&doc={}&vc={}", pkg_name, vc);
//     let body_bytes = body.into_bytes();

//     let resp = execute_request_v2("purchase", None, Some(&body_bytes), None, gsf_id, token)?;

//     // dbg!(&resp);

//     match resp {
//         ResponseWrapper {
//             commands, payload, ..
//         } => match (commands.into_option(), payload.into_option()) {
//             (_, Some(payload)) => Ok(payload.buyResponse.into_option()),
//             (Some(commands), _) => Err(commands.displayErrorMessage.unwrap().into()),
//             _ => unimplemented!(),
//         }, // ResponseWrapper { commands: SingularPtrField<ServerCommands>::some(commands), .. } => Err(commands.displayErrorMessage)
//     }
//     // if let Some(payload) = resp.payload.into_option() {
//     //     Ok(payload.buyResponse.into_option())
//     // } else {
//     //     Ok(None)
//     // }
// }

// /// Lower level Play Store request, used by APIs but exposed for specialized
// /// requests. Returns a `ResponseWrapper` which depending on the request
// /// populates different fields/values.
// pub fn execute_request_v2(
//     endpoint: &str,
//     query: Option<HashMap<&str, &str>>,
//     msg: Option<&[u8]>,
//     content_type: Option<&str>,
//     gsf_id: &str,
//     token: &str,
// ) -> Result<ResponseWrapper, Box<Error>> {
//     let client = reqwest::Client::new();

//     let mut url = Url::parse(&format!(
//         "{}/{}",
//         "https://android.clients.google.com/fdfe", endpoint
//     ))?;

//     let config = BuildConfiguration {
//         ..Default::default()
//     };

//     let mut headers = HeaderMap::new();
//     headers.insert(
//         reqwest::header::USER_AGENT,
//         HeaderValue::from_str(&config.user_agent())?,
//     );
//     headers.insert("Accept-Language", HeaderValue::from_static("en_US"));
//     headers.insert(
//         "Authorization",
//         HeaderValue::from_str(&format!("GoogleLogin auth={}", token))?,
//     );
//     headers.insert(
//         "X-DFE-Enabled-Experiments",
//         HeaderValue::from_static("cl:billing.select_add_instrument_by_default"),
//     );
//     headers.insert("X-DFE-Unsupported-Experiments", HeaderValue::from_static("nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes"));
//     headers.insert("X-DFE-Device-Id", HeaderValue::from_str(&gsf_id)?);
//     headers.insert(
//         "X-DFE-Client-Id",
//         HeaderValue::from_static("am-android-google"),
//     );
//     headers.insert(
//         "X-DFE-SmallestScreenWidthDp",
//         HeaderValue::from_static("320"),
//     );
//     headers.insert("X-DFE-Filter-Level", HeaderValue::from_static("3"));
//         (*self.client).post(DEFAULT_LOGIN_URL).body(form_body).send()?;
//     headers.insert("X-DFE-No-Prefetch", HeaderValue::from_static("true"));

//     if let Some(content_type) = content_type {
//         headers.insert("Content-Type", HeaderValue::from_str(content_type)?);
//     } else {
//         headers.insert(
//             "Content-Type",
//             HeaderValue::from_static("application/x-www-form-urlencoded; charset=UTF-8"),
//         );
//     }

//     if let Some(query) = query {
//         let mut queries = url.query_pairs_mut();
//         for (key, val) in query {
//             queries.append_pair(key, val);
//         }
//     }

//     let mut res = if let Some(msg) = msg {
//         client
//             .post(url)
//             .headers(headers)
//             .body(msg.to_owned())
//             .send()?
//     } else {
//         client.get(url).headers(headers).send()?
//     };

//     // dbg!(&res);

//     let mut buf = Vec::new();
//     res.copy_to(&mut buf)?;
//     let mut resp = ResponseWrapper::new();
//     resp.merge_from_bytes(&buf)?;
//     Ok(resp)
// }

// /// Handles logging into Google Play Store, retrieving a set of tokens from
// /// the server that can be used for future requests.
// /// The `gsf_id` is obtained by retrieving your
// /// [GSF id](https://blog.onyxbits.de/what-exactly-is-a-gsf-id-where-do-i-get-it-from-and-why-should-i-care-2-12/).
// /// You can also get your **GSF ID**  using this following [device id app](https://play.google.com/store/apps/details?id=com.evozi.deviceid&hl=en)
// /// Note that you don't want the Android ID here, but the GSF id.
// pub fn login(
//     username: &str,
//     password: &str,
//     gsf_id: &str,
// ) -> Result<HashMap<String, String>, Box<Error>> {
//     use consts::defaults::DEFAULT_LOGIN_URL;

//     let login_req = build_login_request(username, password, gsf_id);

//     let mut easy = curl::easy::Easy::new();
//     easy.url(DEFAULT_LOGIN_URL)?;
//     easy.useragent(consts::defaults::DEFAULT_AUTH_USER_AGENT)?;
//     easy.post(true)?;
//     let form_body = login_req.form_post();
//     easy.post_fields_copy(form_body.as_bytes())?;

//     let mut buf = Vec::new();
//     {
//         let mut transfer = easy.transfer();
//         transfer.write_function(|data| {
//             buf.extend_from_slice(data);
//             Ok(data.len())
//         })?;
//         transfer.perform()?;
//     }

//     let reply = parse_form_reply(&std::str::from_utf8(&buf).unwrap());
//     Ok(reply)
// }
// /// A trait that provides a convenience method for using URL-encoded query paramaters in a URL with `curl::Easy`
// pub trait QueryParams {
//     fn url_query(&mut self, url: &str, query: HashMap<&str, &str>) -> Result<String, curl::Error>;
// }

// impl QueryParams for Easy {
//     /// Convenience method to set the `url` with query parameters.
//     fn url_query(&mut self, url: &str, query: HashMap<&str, &str>) -> Result<String, curl::Error> {
//         let mut res = vec![];
//         for (key, val) in query.into_iter() {
//             res.push(format!("{}={}", key, self.url_encode(val.as_bytes())));
//         }
//         let url = format!("{}?{}", url, res.join("&"));
//         self.url(&url)?;
//         Ok(url)
//     }
// }
