use ::{
    anyhow::Context as _,
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
    tokio::net::{self, TcpStream},
    tower_service::Service,
};

pub(crate) struct Config {
    pub(crate) domain: String,
    pub(crate) resolver: ResolverConfig,
    pub(crate) deny_user_agents: Regex,
}

pub(crate) enum ResolverConfig {
    System,
    TrustDns(trust_dns_resolver::config::ResolverConfig),
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
        let resolver = match config.resolver {
            ResolverConfig::System => Resolver::System,
            ResolverConfig::TrustDns(config) => {
                let resolver = trust_dns_resolver::AsyncResolver::tokio(
                    config,
                    trust_dns_resolver::config::ResolverOpts::default(),
                )
                .context("failed to create DNS resolver")?;
                Resolver::TrustDns(Arc::new(resolver))
            }
        };

        let http_connector = Connector { resolver };

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

#[derive(Clone)]
enum Resolver {
    System,
    TrustDns(Arc<trust_dns_resolver::TokioAsyncResolver>),
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
            let addresses: Vec<_> = match this.resolver {
                Resolver::System => net::lookup_host(host)
                    .await
                    .map_err(ConnectorError::SystemDns)?
                    .collect(),
                Resolver::TrustDns(resolver) => resolver
                    .lookup_ip(host)
                    .await
                    .map_err(ConnectorError::TrustDns)?
                    .iter()
                    .map(|ip| SocketAddr::new(ip, port))
                    .collect(),
            };
            TcpStream::connect(&*addresses)
                .await
                .map_err(ConnectorError::ConnectError)
        })
    }
}

#[derive(Debug)]
enum ConnectorError {
    NoHost(NoHostError),
    SystemDns(io::Error),
    TrustDns(trust_dns_resolver::error::ResolveError),
    ConnectError(io::Error),
}

impl Error for ConnectorError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(match self {
            Self::NoHost(e) => e,
            Self::SystemDns(e) | Self::ConnectError(e) => e,
            Self::TrustDns(e) => e,
        })
    }
}

impl Display for ConnectorError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // TODO: better messages
        f.write_str("failed to connect to URI")
    }
}

/// Failed to resolve DNS because there was no host.
#[derive(Debug)]
struct NoHostError;

impl Display for NoHostError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("URI did not contain host")
    }
}

impl Error for NoHostError {}
