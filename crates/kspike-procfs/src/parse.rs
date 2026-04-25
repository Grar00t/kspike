//! Hex helpers for procfs.

pub fn hex32_be(s: &str) -> Option<u32> { u32::from_str_radix(s, 16).ok() }

pub fn parse_proc_tcp_addr(field: &str) -> Option<(std::net::IpAddr, u16)> {
    let mut it = field.split(':');
    let addr_hex = it.next()?;
    let port_hex = it.next()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if addr_hex.len() == 8 {
        let v = hex32_be(addr_hex)?;
        // /proc/net/tcp gives little-endian-on-disk for ipv4.
        let octets = v.to_le_bytes();
        Some((std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), port))
    } else if addr_hex.len() == 32 {
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&addr_hex[2*i..2*i+2], 16).ok()?;
        }
        // ipv6 in /proc is also LE per 32-bit word; reverse each 4-byte chunk.
        for c in 0..4 {
            let s = c*4;
            bytes[s..s+4].reverse();
        }
        Some((std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes)), port))
    } else { None }
}

pub fn tcp_state_name(s: u8) -> &'static str {
    match s {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0a => "LISTEN",
        0x0b => "CLOSING",
        _    => "UNKNOWN",
    }
}
