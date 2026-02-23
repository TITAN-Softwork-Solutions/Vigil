use crate::{
    output::alerts::Alert,
    support::config::{EndpointAlertConfig, EndpointTransport},
};
use anyhow::{Context, Result};
use std::{
    io::Write,
    net::{TcpStream, ToSocketAddrs, UdpSocket},
    time::Duration,
};

#[derive(Clone)]
pub struct EndpointAlerter {
    enabled: bool,
    target: String,
    transport: EndpointTransport,
    timeout: Duration,
    retries: usize,
}

impl EndpointAlerter {
    pub fn from_config(cfg: &EndpointAlertConfig) -> Self {
        Self {
            enabled: cfg.enabled,
            target: cfg.endpoint.trim().to_string(),
            transport: cfg.transport.clone(),
            timeout: Duration::from_millis(cfg.connect_timeout_ms.max(100)),
            retries: cfg.retries.max(1),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn send(&self, alert: &Alert) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }

        let body = serde_json::to_vec(alert)?;
        let mut attempt = 0usize;
        loop {
            attempt += 1;
            let result = match self.transport {
                EndpointTransport::Udp => self.send_udp(&body),
                EndpointTransport::Tcp => self.send_tcp(&body),
            };

            if result.is_ok() || attempt >= self.retries {
                return result;
            }
        }
    }

    fn send_udp(&self, body: &[u8]) -> Result<()> {
        let addr = self.resolve_first_addr()?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.send_to(body, addr)?;
        Ok(())
    }

    fn send_tcp(&self, body: &[u8]) -> Result<()> {
        let addr = self.resolve_first_addr()?;
        let mut stream = TcpStream::connect_timeout(&addr, self.timeout)?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(body)?;
        stream.write_all(b"\n")?;
        Ok(())
    }

    fn resolve_first_addr(&self) -> Result<std::net::SocketAddr> {
        self.target
            .to_socket_addrs()
            .with_context(|| format!("invalid endpoint address '{}'", self.target))?
            .next()
            .context("endpoint resolved to no addresses")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::config::{EndpointAlertConfig, EndpointTransport};
    use std::{
        io::Read,
        net::{TcpListener, UdpSocket},
        thread,
        time::Duration,
    };

    fn test_alert() -> Alert {
        Alert::new(
            42,
            "C:\\test\\proc.exe".to_string(),
            "C:\\secret\\cookies.db".to_string(),
            "Cookie Store".to_string(),
            12,
            "protected_resource_access",
            "unit-test",
        )
    }

    #[test]
    fn from_config_carries_core_settings() {
        let cfg = EndpointAlertConfig {
            enabled: true,
            endpoint: "127.0.0.1:9999".to_string(),
            transport: EndpointTransport::Tcp,
            connect_timeout_ms: 2500,
            retries: 3,
        };

        let alerter = EndpointAlerter::from_config(&cfg);
        assert!(alerter.enabled);
        assert_eq!(alerter.target, "127.0.0.1:9999");
        matches!(alerter.transport, EndpointTransport::Tcp);
        assert_eq!(alerter.timeout, Duration::from_millis(2500));
        assert_eq!(alerter.retries, 3);
    }

    #[test]
    fn resolve_first_addr_rejects_bad_endpoint() {
        let cfg = EndpointAlertConfig {
            enabled: true,
            endpoint: "bad:endpoint".to_string(),
            transport: EndpointTransport::Udp,
            connect_timeout_ms: 500,
            retries: 1,
        };
        let alerter = EndpointAlerter::from_config(&cfg);
        let err = alerter.resolve_first_addr().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid endpoint"));
    }

    #[test]
    fn send_udp_delivers_json_payload() {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("bind udp receiver");
        rx.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let addr = rx.local_addr().expect("local addr");

        let recv_thread = thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let (n, _) = rx.recv_from(&mut buf).expect("recv udp");
            buf.truncate(n);
            buf
        });

        let cfg = EndpointAlertConfig {
            enabled: true,
            endpoint: addr.to_string(),
            transport: EndpointTransport::Udp,
            connect_timeout_ms: 1000,
            retries: 1,
        };
        let alerter = EndpointAlerter::from_config(&cfg);
        let expected = test_alert();
        alerter.send(&expected).expect("send udp");

        let got = recv_thread.join().expect("join recv thread");
        let decoded: Alert = serde_json::from_slice(&got).expect("decode alert json");
        assert_eq!(decoded.pid, expected.pid);
        assert_eq!(decoded.process, expected.process);
        assert_eq!(decoded.target, expected.target);
    }

    #[test]
    fn send_tcp_delivers_json_line_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tcp listener");
        listener
            .set_nonblocking(false)
            .expect("listener blocking mode");
        let addr = listener.local_addr().expect("local addr");

        let recv_thread = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set timeout");
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).expect("read stream");
            buf
        });

        let cfg = EndpointAlertConfig {
            enabled: true,
            endpoint: addr.to_string(),
            transport: EndpointTransport::Tcp,
            connect_timeout_ms: 1000,
            retries: 1,
        };
        let alerter = EndpointAlerter::from_config(&cfg);
        let expected = test_alert();
        alerter.send(&expected).expect("send tcp");

        let got = recv_thread.join().expect("join recv thread");
        assert!(got.ends_with(b"\n"));
        let decoded: Alert =
            serde_json::from_slice(got.trim_ascii_end()).expect("decode alert json line");
        assert_eq!(decoded.pid, expected.pid);
        assert_eq!(decoded.process, expected.process);
        assert_eq!(decoded.target, expected.target);
    }
}
