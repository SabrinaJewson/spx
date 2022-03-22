use ::{
    regex::Regex,
    serde::{
        de::{self, Deserializer},
        Deserialize,
    },
    std::{
        fmt::{self, Formatter},
        net::{IpAddr, SocketAddr},
        path::PathBuf,
    },
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    http_port: u16,
    https_port: u16,
    domain: String,
    resolver: Resolver,
    deny_user_agents: serde_regex::Serde<Regex>,
    tls_certificate: TlsCertificate,
}

pub(crate) enum Resolver {
    System,
    TrustDns(trust_dns_resolver::config::ResolverConfig),
}

macro_rules! with_trust_dns_resolvers {
    ($($callback:tt)*) => {
        $($callback)*! {
            google: "Google's DNS resolvers",
            cloudflare: "Cloudflare's DNS resolvers",
            quad9: "Quad9's DNS resolvers",
        }
    };
}

impl<'de> Deserialize<'de> for Resolver {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Resolver;

            fn expecting(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("a DNS resolver")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                macro_rules! gen_match_arms {
                    ($($name:ident: $_desc:literal,)*) => {
                        match v {
                            "system" => Resolver::System,
                            $(stringify!($name) => {
                                Resolver::TrustDns(trust_dns_resolver::config::ResolverConfig::$name())
                            })*
                            _ => return Err(de::Error::unknown_variant(
                                v,
                                &[$(stringify!($name),)*],
                            )),
                        }
                    };
                }
                Ok(with_trust_dns_resolvers!(gen_match_arms))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut config = trust_dns_resolver::config::ResolverConfig::new();

                while let Some(ip_addr) = seq.next_element::<IpAddr>()? {
                    config.add_name_server(trust_dns_resolver::config::NameServerConfig {
                        socket_addr: SocketAddr::new(ip_addr, 53),
                        protocol: trust_dns_resolver::config::Protocol::default(),
                        tls_dns_name: None,
                        trust_nx_responses: true,
                        bind_addr: None,
                    });
                }

                Ok(Resolver::TrustDns(config))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TlsCertificate {
    chain: PathBuf,
    key: PathBuf,
}

with_trust_dns_resolvers!(gen_initial_config);
macro_rules! gen_initial_config {
    ($($resolver_name:ident: $resolver_desc:literal,)*) => {
pub(crate) const INITIAL_CONFIG: &str = concat!(r#"# SPX configuration file

# The port to serve plain HTTP on.
http_port = 80

# The port to serve HTTPS on.
https_port = 443

# The domain name of your server. Proxy URLs will look like "www.rust-lang.org.example.com".
domain = "example.com"

# The DNS resolver to use.
#
# Possible values:
# - "system": Use the system default resolver."#,
$(concat!("\n# - \"", stringify!($resolver_name), "\": Use ", $resolver_desc, "."),)* r#"
# - An array of IP addresses to use as DNS servers
resolver = "system"

# A regex that can be used to ban certain user agents.
#
# This default list comes from https://stackoverflow.com/a/24820722
deny_user_agents = """(?x)
    google|bing|yandex|msnbot
    |AltaVista|Googlebot|Slurp|BlackWidow|Bot|ChinaClaw|Custo|DISCo|Download|Demon|eCatch|EirGrabber|EmailSiphon|EmailWolf|SuperHTTP|Surfbot|WebWhacker
    |Express|WebPictures|ExtractorPro|EyeNetIE|FlashGet|GetRight|GetWeb!|Go!Zilla|Go-Ahead-Got-It|GrabNet|Grafula|HMView|Go!Zilla|Go-Ahead-Got-It
    |rafula|HMView|HTTrack|Stripper|Sucker|Indy|InterGET|Ninja|JetCar|Spider|larbin|LeechFTP|Downloader|tool|Navroad|NearSite|NetAnts|tAkeOut|WWWOFFLE
    |GrabNet|NetSpider|Vampire|NetZIP|Octopus|Offline|PageGrabber|Foto|pavuk|pcBrowser|RealDownload|ReGet|SiteSnagger|SmartDownload|SuperBot|WebSpider
    |Teleport|VoidEYE|Collector|WebAuto|WebCopier|WebFetch|WebGo|WebLeacher|WebReaper|WebSauger|eXtractor|Quester|WebStripper|WebZIP|Wget|Widow|Zeus
    |Twengabot|htmlparser|libwww|Python|perl|urllib|scan|Curl|email|PycURL|Pyth|PyQ|WebCollector|WebCopy|webcraw
"""

# The TLS certificate to use when serving HTTPS
[tls_certificate]
chain = "/path/to/your/cert/fullchain.pem"
key = "/path/to/your/cert/privkey.pem"
"#);
    };
}
use gen_initial_config;

#[test]
fn initial_config_is_valid() {
    toml::from_str::<Config>(INITIAL_CONFIG).unwrap();
}
