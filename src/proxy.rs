use ::{
    hyper::http::{self, Uri},
    regex::Regex,
    std::{
        convert::Infallible,
        error::Error,
        fmt::{self, Display, Formatter},
        future::Future,
        io,
        net::SocketAddr,
        pin::Pin,
        sync::Arc,
        task::{self, Poll},
    },
    tokio::net::TcpStream,
    tower_service::Service,
};

pub(crate) struct Config {
    pub(crate) domain: String,
    pub(crate) resolver: resolver::Config,
    pub(crate) deny_user_agents: Regex,
}

#[derive(Clone)]
pub(crate) struct Proxy {
    inner: Arc<ProxyInner>,
}

struct ProxyInner {
    domain: String,
    deny_user_agents: Regex,
    client: hyper::Client<hyper_rustls::HttpsConnector<Connector>>,
}

impl Proxy {
    pub(crate) fn new(config: Config) -> anyhow::Result<Self> {
        let http_connector = Connector {
            resolver: Resolver::new(config.resolver)?,
        };

        let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector);

        let client = hyper::Client::builder().build(https_connector);

        let inner = Arc::new(ProxyInner {
            domain: config.domain,
            deny_user_agents: config.deny_user_agents,
            client,
        });

        Ok(Proxy { inner })
    }
}

impl Service<http::Request<hyper::Body>> for Proxy {
    type Response = http::Response<hyper::Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: http::Request<hyper::Body>) -> Self::Future {
        todo!()
    }
}

#[derive(Clone)]
struct Connector {
    resolver: Resolver,
}

impl Service<Uri> for Connector {
    type Response = TcpStream;
    type Error = ConnectorError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let host = uri.host().ok_or(ConnectorError::NoHost(NoHostError))?;
            let port = uri.port_u16().unwrap_or_else(|| match uri.scheme_str() {
                Some("https") => 443,
                _ => 80,
            });

            let addresses: Vec<_> = this
                .resolver
                .resolve(host)
                .await
                .map_err(ConnectorError::Dns)?
                .map(|ip| SocketAddr::new(ip, port))
                .collect();

            TcpStream::connect(&*addresses)
                .await
                .map_err(ConnectorError::Tcp)
        })
    }
}

#[derive(Debug)]
enum ConnectorError {
    NoHost(NoHostError),
    Dns(resolver::Error),
    Tcp(io::Error),
}

impl Display for ConnectorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("failed to connect to URI")
    }
}

impl Error for ConnectorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::NoHost(e) => e,
            Self::Dns(e) => e,
            Self::Tcp(e) => e,
        })
    }
}

#[derive(Debug)]
struct NoHostError;

impl Display for NoHostError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("URI did not contain host")
    }
}

impl Error for NoHostError {}

pub(crate) mod resolver {
    use ::{
        anyhow::Context as _,
        std::{
            error::Error as StdError,
            fmt::{self, Display, Formatter},
            io,
            net::IpAddr,
            sync::Arc,
        },
        tokio::net,
    };

    pub(crate) enum Config {
        System,
        TrustDns(trust_dns_resolver::config::ResolverConfig),
    }

    #[derive(Clone)]
    pub(super) enum Resolver {
        System,
        TrustDns(Arc<trust_dns_resolver::TokioAsyncResolver>),
    }

    impl Resolver {
        pub(super) fn new(config: Config) -> anyhow::Result<Self> {
            Ok(match config {
                Config::System => Self::System,
                Config::TrustDns(config) => {
                    let resolver = trust_dns_resolver::AsyncResolver::tokio(
                        config,
                        trust_dns_resolver::config::ResolverOpts::default(),
                    )
                    .context("failed to create DNS resolver")?;
                    Self::TrustDns(Arc::new(resolver))
                }
            })
        }
    }

    impl Resolver {
        pub(super) async fn resolve<'a>(
            &self,
            host: &'a str,
        ) -> Result<impl Iterator<Item = IpAddr> + 'a, Error> {
            enum Either<A, B> {
                A(A),
                B(B),
            }

            impl<Item, A: Iterator<Item = Item>, B: Iterator<Item = Item>> Iterator for Either<A, B> {
                type Item = Item;
                fn next(&mut self) -> Option<Self::Item> {
                    match self {
                        Self::A(a) => a.next(),
                        Self::B(b) => b.next(),
                    }
                }
            }

            Ok(match self {
                Self::System => Either::A(
                    net::lookup_host(host)
                        .await
                        .map_err(Error::System)?
                        .map(|addr| addr.ip()),
                ),
                Self::TrustDns(resolver) => Either::B(
                    resolver
                        .lookup_ip(host)
                        .await
                        .map_err(Error::TrustDns)?
                        .into_iter(),
                ),
            })
        }
    }

    #[derive(Debug)]
    pub(super) enum Error {
        System(io::Error),
        TrustDns(trust_dns_resolver::error::ResolveError),
    }

    impl Display for Error {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            f.write_str("failed to resolve DNS name")
        }
    }

    impl StdError for Error {
        fn source(&self) -> Option<&(dyn StdError + 'static)> {
            Some(match self {
                Self::System(e) => e,
                Self::TrustDns(e) => e,
            })
        }
    }
}
use resolver::Resolver;
