//! Firewall rule management.
//!
//! Provides traits and implementations for installing/removing
//! firewall rules required by the NFQ and transparent proxy modes.

/// Trait for managing firewall rules.
pub trait FirewallManager {
    /// Install the required firewall rules.
    fn install_rules(&self) -> anyhow::Result<()>;

    /// Remove all rules installed by this manager.
    fn cleanup_rules(&self) -> anyhow::Result<()>;
}

/// Linux iptables/nftables rule manager.
#[cfg(target_os = "linux")]
pub struct IptablesManager {
    /// NFQUEUE number to redirect to.
    pub queue_num: u16,
    /// Ports to intercept.
    pub ports: Vec<u16>,
    /// Whether rules have been installed.
    installed: bool,
}

#[cfg(target_os = "linux")]
impl IptablesManager {
    pub fn new(queue_num: u16, ports: Vec<u16>) -> Self {
        Self {
            queue_num,
            ports,
            installed: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl FirewallManager for IptablesManager {
    fn install_rules(&self) -> anyhow::Result<()> {
        use std::process::Command;
        for port in &self.ports {
            // Outgoing TCP to specified ports, first 6 packets of connection.
            let status = Command::new("iptables")
                .args([
                    "-A", "OUTPUT",
                    "-p", "tcp",
                    "--dport", &port.to_string(),
                    "-m", "connbytes",
                    "--connbytes", "1:6",
                    "--connbytes-dir", "original",
                    "--connbytes-mode", "packets",
                    "-j", "NFQUEUE",
                    "--queue-num", &self.queue_num.to_string(),
                    "--queue-bypass",
                ])
                .status()?;

            if !status.success() {
                anyhow::bail!("iptables rule installation failed for port {}", port);
            }
        }

        tracing::info!(
            queue_num = self.queue_num,
            ports = ?self.ports,
            "iptables rules installed"
        );
        Ok(())
    }

    fn cleanup_rules(&self) -> anyhow::Result<()> {
        use std::process::Command;
        for port in &self.ports {
            let _ = Command::new("iptables")
                .args([
                    "-D", "OUTPUT",
                    "-p", "tcp",
                    "--dport", &port.to_string(),
                    "-m", "connbytes",
                    "--connbytes", "1:6",
                    "--connbytes-dir", "original",
                    "--connbytes-mode", "packets",
                    "-j", "NFQUEUE",
                    "--queue-num", &self.queue_num.to_string(),
                    "--queue-bypass",
                ])
                .status();
        }
        tracing::info!("iptables rules cleaned up");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for IptablesManager {
    fn drop(&mut self) {
        if self.installed {
            let _ = self.cleanup_rules();
        }
    }
}

/// Linux iptables REDIRECT rule manager for transparent proxy mode.
///
/// Uses `iptables -t nat ... -j REDIRECT` to divert outbound connections
/// to the transparent proxy. Rules are automatically cleaned up on Drop.
#[cfg(target_os = "linux")]
pub struct IptablesRedirectManager {
    /// Port where the transparent proxy listens.
    pub proxy_port: u16,
    /// Destination ports to intercept (typically [80, 443]).
    pub intercept_ports: Vec<u16>,
    /// Whether rules have been installed.
    installed: bool,
}

#[cfg(target_os = "linux")]
impl IptablesRedirectManager {
    pub fn new(proxy_port: u16, intercept_ports: Vec<u16>) -> Self {
        Self {
            proxy_port,
            intercept_ports,
            installed: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl FirewallManager for IptablesRedirectManager {
    fn install_rules(&self) -> anyhow::Result<()> {
        use std::process::Command;
        for port in &self.intercept_ports {
            let status = Command::new("iptables")
                .args([
                    "-t", "nat",
                    "-A", "OUTPUT",
                    "-p", "tcp",
                    "--dport", &port.to_string(),
                    "-j", "REDIRECT",
                    "--to-ports", &self.proxy_port.to_string(),
                ])
                .status()?;

            if !status.success() {
                anyhow::bail!(
                    "iptables REDIRECT rule installation failed for port {}",
                    port
                );
            }
        }

        tracing::info!(
            proxy_port = self.proxy_port,
            ports = ?self.intercept_ports,
            "iptables REDIRECT rules installed"
        );
        Ok(())
    }

    fn cleanup_rules(&self) -> anyhow::Result<()> {
        use std::process::Command;
        for port in &self.intercept_ports {
            let _ = Command::new("iptables")
                .args([
                    "-t", "nat",
                    "-D", "OUTPUT",
                    "-p", "tcp",
                    "--dport", &port.to_string(),
                    "-j", "REDIRECT",
                    "--to-ports", &self.proxy_port.to_string(),
                ])
                .status();
        }
        tracing::info!("iptables REDIRECT rules cleaned up");
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for IptablesRedirectManager {
    fn drop(&mut self) {
        if self.installed {
            let _ = self.cleanup_rules();
        }
    }
}
