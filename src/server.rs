use {
    crate::proxy::{self, Proxy},
    ::{
        anyhow::{bail, Context as _},
        hyper::server::conn::Http,
        std::{
            io,
            net::SocketAddr,
            path::{Path, PathBuf},
            sync::{Arc, Mutex},
            time::Duration,
        },
        tokio::{
            io::{AsyncRead, AsyncWrite},
            net::{TcpListener, TcpStream},
            time, try_join,
        },
        tokio_rustls::{rustls, TlsAcceptor},
    },
};

pub(crate) struct Config {
    pub(crate) http_port: u16,
    pub(crate) https_port: u16,
    pub(crate) tls: TlsConfig,
    pub(crate) proxy: proxy::Config,
}

pub(crate) struct TlsConfig {
    pub(crate) refresh: Duration,
    pub(crate) chain: PathBuf,
    pub(crate) key: PathBuf,
}

pub(crate) fn run(config: Config) -> anyhow::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("failed to create Tokio runtime")?
        .block_on(run_async(config))
}

async fn run_async(config: Config) -> anyhow::Result<()> {
    let http = Arc::new(Http::new());
    let proxy = Proxy::new(config.proxy)?;

    let http_task = tokio::task::spawn(serve_http(config.http_port, http.clone(), proxy.clone()));
    let https_task = tokio::task::spawn(serve_https(config.https_port, config.tls, http, proxy));

    let http_task = async { http_task.await.unwrap() };
    let https_task = async { https_task.await.unwrap() };

    try_join!(http_task, https_task)?;

    Ok(())
}

async fn serve_http(port: u16, http: Arc<Http>, proxy: Proxy) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("failed to bind to port {port}"))?;

    loop {
        let (tcp_stream, _) = accept_tcp(&listener).await;
        let connection = serve_connection(http.clone(), tcp_stream, proxy.clone());
        tokio::task::spawn(connection);
    }
}

async fn serve_https(
    port: u16,
    tls: TlsConfig,
    http: Arc<Http>,
    proxy: Proxy,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))
        .await
        .with_context(|| format!("failed to bind to port {port}"))?;

    let tls_config = refreshed_tls(tls).await?;

    loop {
        let (tcp_stream, _) = accept_tcp(&listener).await;

        let accept = tls_config.lock().unwrap().accept(tcp_stream);

        let (http, proxy) = (http.clone(), proxy.clone());
        tokio::task::spawn(async move {
            let tls_stream = match time::timeout(Duration::from_millis(200), accept).await {
                Ok(Ok(tls_stream)) => tls_stream,
                Ok(Err(_)) | Err(_) => return,
            };
            serve_connection(http, tls_stream, proxy).await;
        });
    }
}

async fn refreshed_tls(tls: TlsConfig) -> anyhow::Result<Arc<Mutex<TlsAcceptor>>> {
    let tls_config = Arc::new(Mutex::new(acceptor(&*tls.chain, &*tls.key).await?));

    tokio::task::spawn({
        let tls_config = tls_config.clone();
        async move {
            time::sleep(tls.refresh).await;
            match acceptor(&*tls.chain, &*tls.key).await {
                Ok(acceptor) => {
                    *tls_config.lock().unwrap() = acceptor;
                }
                Err(e) => log::error!("{e:?}"),
            }
        }
    });

    Ok(tls_config)
}

async fn acceptor(chain: &Path, key: &Path) -> anyhow::Result<TlsAcceptor> {
    let config = tls_config(chain, key)
        .await
        .context("failed to set up TLS")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn tls_config(chain: &Path, key: &Path) -> anyhow::Result<rustls::ServerConfig> {
    let (chain, key) = (chain.to_owned(), key.to_owned());
    let (certificates, key) = tokio::task::spawn_blocking(move || {
        let chain = std::fs::read(chain).context("failed to open chain file")?;
        let key = std::fs::read(key).context("failed to open key file")?;

        let certificates = rustls_pemfile::certs(&mut &*chain)
            .context("failed to extract certificates from chain PEM file")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

        let key = match rustls_pemfile::read_one(&mut &*key)
            .context("failed to extract TLS private key from PEM file")?
        {
            Some(rustls_pemfile::Item::RSAKey(bytes) | rustls_pemfile::Item::PKCS8Key(bytes)) => {
                rustls::PrivateKey(bytes)
            }
            _ => bail!("no private key found in PEM file"),
        };

        Ok((certificates, key))
    })
    .await
    .unwrap()?;

    let mut config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .context("TLS private key is invalid")?;

    config.alpn_protocols.push(b"h2".to_vec());
    config.alpn_protocols.push(b"http/1.1".to_vec());

    Ok(config)
}

async fn accept_tcp(listener: &TcpListener) -> (TcpStream, SocketAddr) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => break (stream, addr),
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::ConnectionReset
                ) => {}
            Err(e) => {
                log::error!("failed to accept: {e}");
                time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

async fn serve_connection<Io>(http: Arc<Http>, io: Io, proxy: Proxy)
where
    Io: AsyncRead + AsyncWrite + Unpin + 'static,
{
    if let Err(e) = http.serve_connection(io, proxy).await {
        log::warn!("connection error: {e}");
    }
}
