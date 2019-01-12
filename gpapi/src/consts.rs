// These are obtained from reversing the Play Store and extracting the public key components from the pem
/// Google Play Public Key (base64 encoded)
pub const GOOGLE_PUB_KEY_B64: &'static str = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ==";
/// Google Play Public modulus (hexstr encoded)
pub const GOOGLE_PUB_MODULUS_HEXSTR: &'static str = "ca26ff56bfbf495b94ed946ebb7ad09da072e5d296318541781cc995af7962c4c28ea9af0822de224865da1dca129942b356a799ca277b2b4577145be175043ddb684546726120a9a2d950d0639b4e7ba4a448d7a901d18a69786c79a884394232b3b11f044d06ca2cd5a0458d1044d573df890c251dcffcb8076b1ffaae67f9";
/// Google Play Public exponent
pub const GOOGLE_PUB_EXP: u32 = 65537;

pub mod defaults {
    pub const DEFAULT_LANGUAGE: &str = "en_US";
    pub const DEFAULT_USE_CACHE: bool = false;
    pub const DEFAULT_DEBUG: bool = false;
    pub const DEFAULT_SDK_VERSION: &str = "23";
    pub const DEFAULT_COUNTRY_CODE: &str = "us";
    pub const DEFAULT_AUTH_USER_AGENT: &str = "GoogleAuth/1.4";
    pub mod api_user_agent {
        pub const DEFAULT_API: &str = "3";
        pub const DEFAULT_VERSION_CODE: &str = "80420700";
        pub const DEFAULT_SDK: &str = "23";
        pub const DEFAULT_DEVICE: &str = "flo";
        pub const DEFAULT_HARDWARE: &str = "flo";
        pub const DEFAULT_PRODUCT: &str = "razor";
        pub const DEFAULT_PLATFORM_VERSION_RELEASE: &str = "6.0.1";
        pub const DEFAULT_MODEL: &str = "Nexus%207";
        pub const DEFAULT_BUILD_ID: &str = "MOB30X";
        pub const DEFAULT_IS_WIDE_SCREEN: &str = "0";
    }
    pub const DEFAULT_FINSKY_AGENT: &str = "Android-Finsky";
    pub const DEFAULT_FINSKY_VERSION: &str = "5.12.7";
    // pub const DEFAULT_API_USER_AGENT: &str = "Android-Finsky/5.12.7 (api=3,versionCode=80420700,sdk=23,device=flo,hardware=flo,product=razor,platformVersionRelease=6.0.1,model=Nexus 7,buildId=MOB30X,isWideScreen=0)";
    pub const DEFAULT_DOWNLOAD_USER_AGENT: &str =
        "AndroidDownloadManager/6.0.1 (Linux; U; Android 6.0.1; Nexus 7 Build/MOB30X)";
    pub const DEFAULT_PRE_FETCH: bool = false;
    pub const DEFAULT_CACHE_INVALIDATION_INTERVAL: i32 = 30000; // 30 sec
    pub const DEFAULT_DEVICE_COUNTRY: &str = "us";
    pub const DEFAULT_CLIENT_ID: &str = "am-android-google";
    pub const DEFAULT_ANDROID_VENDING: &str = "com.android.vending";
    pub const DEFAULT_ACCOUNT_TYPE: &str = "HOSTED_OR_GOOGLE";
    pub const DEFAULT_SERVICE: &str = "androidmarket";
    pub const DEFAULT_LOGIN_URL: &str = "https://android.clients.google.com/auth";
    // pub const DEFAULT_LOGIN_URL: &str = "http://localhost:9990/auth";
    // const unsupported_experiments = [ "nocache:billing.use_charging_poller", "market_emails", "buyer_currency", "prod_baseline", "checkin.set_asset_paid_app_field", "shekel_test", "content_ratings", "buyer_currency_in_app", "nocache:encrypted_apk", "recent_changes" ],
    // const enabled_experiments = vec!["cl:billing.select_add_instrument_by_default" ];
}
