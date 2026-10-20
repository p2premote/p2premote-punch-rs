//! Android IGD transport: protect every socket before bind/connect so gateway
//! traffic cannot be captured by the VPN, including renewal and deletion.
use async_trait::async_trait;
use igd_next::{
    aio::{Gateway, Provider},
    RequestError, SearchError, SearchOptions,
};
use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Mutex,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpSocket,
};
use xmltree::Element;

type DiscoveryHook = Box<dyn Fn(bool) -> bool + Send + Sync>;
static DISCOVERY_HOOK: Mutex<Option<DiscoveryHook>> = Mutex::new(None);
pub fn set_discovery_hook(hook: Option<DiscoveryHook>) {
    *DISCOVERY_HOOK.lock().unwrap() = hook;
}
pub struct DiscoveryGuard;
impl DiscoveryGuard {
    pub fn begin() -> Option<Self> {
        DISCOVERY_HOOK
            .lock()
            .unwrap()
            .as_ref()
            .filter(|hook| hook(true))
            .map(|_| Self)
    }
}
impl Drop for DiscoveryGuard {
    fn drop(&mut self) {
        if let Some(hook) = DISCOVERY_HOOK.lock().unwrap().as_ref() {
            hook(false);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Protected;
#[async_trait]
impl Provider for Protected {
    async fn send_async(url: &str, action: &str, body: &str) -> Result<String, RequestError> {
        Ok(String::from_utf8(http(url, Some((action, body))).await?)?)
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn endpoint(url: &str) -> io::Result<(SocketAddr, String)> {
    if url.contains(['\r', '\n']) {
        return Err(invalid("invalid URL"));
    }
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| invalid("IGD requires HTTP"))?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let addr = host
        .parse()
        .or_else(|_| {
            host.parse::<Ipv4Addr>()
                .map(|ip| SocketAddr::from((ip, 80)))
        })
        .map_err(|_| invalid("IGD URL must contain a literal IP"))?;
    Ok((addr, format!("/{path}")))
}
fn resource(addr: SocketAddr, path: &str) -> io::Result<String> {
    if path.starts_with("http://") {
        if endpoint(path)?.0 != addr {
            return Err(invalid("cross-origin IGD resource"));
        }
        Ok(path.to_owned())
    } else {
        Ok(format!("http://{addr}/{}", path.trim_start_matches('/')))
    }
}

const LIMIT: usize = 256 * 1024;
fn decode(bytes: &[u8], eof: bool) -> io::Result<Option<Vec<u8>>> {
    if bytes.len() > LIMIT {
        return Err(invalid("IGD response too large"));
    }
    let Some(end) = bytes.windows(4).position(|s| s == b"\r\n\r\n") else {
        if eof || bytes.len() > 16384 {
            return Err(invalid("invalid HTTP headers"));
        }
        return Ok(None);
    };
    let headers =
        std::str::from_utf8(&bytes[..end]).map_err(|_| invalid("invalid HTTP headers"))?;
    let status = headers.lines().next().unwrap_or_default();
    if !status.starts_with("HTTP/1.")
        || status
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .is_none()
    {
        return Err(invalid("invalid HTTP status"));
    }
    let body = &bytes[end + 4..];
    let mut length = None;
    let mut chunked = false;
    for line in headers.lines().skip(1) {
        if let Some((key, value)) = line.split_once(':') {
            if key.eq_ignore_ascii_case("content-length") {
                length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| invalid("bad content length"))?,
                );
            }
            if key.eq_ignore_ascii_case("transfer-encoding") {
                chunked = value.trim().eq_ignore_ascii_case("chunked");
            }
        }
    }
    if chunked {
        let mut remaining = body;
        let mut output = Vec::new();
        loop {
            let Some(end) = remaining.windows(2).position(|s| s == b"\r\n") else {
                break;
            };
            let size =
                std::str::from_utf8(&remaining[..end]).map_err(|_| invalid("invalid chunk"))?;
            let size = usize::from_str_radix(size.split(';').next().unwrap().trim(), 16)
                .map_err(|_| invalid("invalid chunk size"))?;
            if size == 0 {
                return Ok(Some(output));
            }
            if size > LIMIT {
                return Err(invalid("chunk too large"));
            }
            remaining = &remaining[end + 2..];
            if remaining.len() < size + 2 {
                break;
            }
            if &remaining[size..size + 2] != b"\r\n" {
                return Err(invalid("invalid chunk terminator"));
            }
            output.extend_from_slice(&remaining[..size]);
            remaining = &remaining[size + 2..];
        }
        if eof {
            return Err(invalid("truncated chunked response"));
        }
        return Ok(None);
    }
    if let Some(length) = length {
        if length > LIMIT {
            return Err(invalid("body too large"));
        }
        if body.len() >= length {
            return Ok(Some(body[..length].to_vec()));
        }
        if eof {
            return Err(invalid("truncated response"));
        }
        return Ok(None);
    }
    Ok(eof.then(|| body.to_vec()))
}

async fn http(url: &str, soap: Option<(&str, &str)>) -> io::Result<Vec<u8>> {
    let (addr, path) = endpoint(url)?;
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    super::super::socketprotect::protect_socket(&socket);
    let mut stream = socket.connect(addr).await?;
    let request = match soap {
        Some((action, body)) => format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: text/xml\r\nSOAPAction: {action}\r\nContent-Length: {}\r\n\r\n{body}", body.len()),
        None => format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    };
    stream.write_all(request.as_bytes()).await?;
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 4096];
        let n = stream.read(&mut buffer).await?;
        bytes.extend_from_slice(&buffer[..n]);
        if let Some(body) = decode(&bytes, n == 0)? {
            return Ok(body);
        }
    }
}

fn text(element: &Element, key: &str) -> Option<String> {
    Some(element.get_child(key)?.get_text()?.into_owned())
}
fn service(element: &Element) -> Option<(String, String)> {
    if element.name == "service"
        && text(element, "serviceType")
            .is_some_and(|t| t.starts_with("urn:schemas-upnp-org:service:WANIPConnection:"))
    {
        return Some((text(element, "controlURL")?, text(element, "SCPDURL")?));
    }
    element
        .children
        .iter()
        .filter_map(|e| e.as_element())
        .find_map(service)
}
fn schema(bytes: &[u8]) -> io::Result<HashMap<String, Vec<String>>> {
    let xml = Element::parse(bytes).map_err(|_| invalid("invalid IGD schema"))?;
    let actions = xml
        .get_child("actionList")
        .ok_or_else(|| invalid("missing actions"))?;
    Ok(actions
        .children
        .iter()
        .filter_map(|e| e.as_element())
        .filter_map(|action| {
            let name = text(action, "name")?;
            let inputs = action
                .get_child("argumentList")
                .map(|args| {
                    args.children
                        .iter()
                        .filter_map(|e| e.as_element())
                        .filter(|e| text(e, "direction").as_deref() == Some("in"))
                        .filter_map(|e| text(e, "name"))
                        .collect()
                })
                .unwrap_or_default();
            Some((name, inputs))
        })
        .collect())
}

pub async fn search_gateway(options: SearchOptions) -> Result<Gateway<Protected>, SearchError> {
    let budget = options.timeout.unwrap_or(std::time::Duration::from_secs(1));
    tokio::time::timeout(budget, async move {
        let socket = super::super::netx::tokio_udp(options.bind_addr, false)?;
        // Explicit multicast interface selection matters on multi-homed phones.
        if let std::net::IpAddr::V4(ip) = options.bind_addr.ip() {
            socket2::SockRef::from(&socket).set_multicast_if_v4(&ip)?;
        }
        socket.send_to(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n", options.broadcast_address).await?;
        let mut buffer = [0; 4096];
        loop {
            let (n, from) = socket.recv_from(&mut buffer).await?;
            let response = String::from_utf8_lossy(&buffer[..n]);
            let Some(location) = response.lines().filter_map(|l| l.split_once(':')).find_map(|(k,v)| k.eq_ignore_ascii_case("location").then(|| v.trim().to_owned())) else { continue; };
            let Ok((addr, root_url)) = endpoint(&location) else { continue; };
            if addr.ip() != from.ip() { continue; }
            let Ok(body) = http(&location, None).await else { continue; };
            let Ok(xml) = Element::parse(body.as_slice()) else { continue; };
            let Some((control, scpd)) = service(&xml) else { continue; };
            let control_url = endpoint(&resource(addr, &control)?)?.1;
            let schema_url = resource(addr, &scpd)?;
            let control_schema = schema(&http(&schema_url, None).await?)?;
            return Ok(Gateway { addr, root_url, control_url, control_schema_url: endpoint(&schema_url)?.1, control_schema, provider: Protected });
        }
    }).await.map_err(|_| SearchError::NoResponseWithinTimeout)?
}

#[cfg(test)]
#[path = "android_tests.rs"]
mod tests;
