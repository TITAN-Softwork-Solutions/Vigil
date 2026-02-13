use crate::{
    alerts::Alert,
    config::{EndpointAlertConfig, EndpointTransport},
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
