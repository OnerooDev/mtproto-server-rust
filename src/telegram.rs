/// Telegram datacenter addresses (v4 + v6).
/// DC IDs: 1–5. Negative IDs = test DCs.
pub const TG_DC_V4: &[(&str, u16)] = &[
    ("149.154.175.50", 443),
    ("149.154.167.51", 443),
    ("149.154.175.100", 443),
    ("149.154.167.91", 443),
    ("91.108.56.130", 443),
];

pub const TG_DC_V6: &[(&str, u16)] = &[
    ("2001:b28:f23d:f001::a", 443),
    ("2001:67c:4e8:f002::a", 443),
    ("2001:b28:f23d:f003::a", 443),
    ("2001:67c:4e8:f004::a", 443),
    ("2001:b28:f23f:f005::a", 443),
];

/// Resolve a Telegram DC id (1-based, possibly negative for test DCs) to an address.
pub fn dc_addr(dc_id: i16, prefer_ipv6: bool) -> (&'static str, u16) {
    let idx = (dc_id.unsigned_abs() as usize).saturating_sub(1);
    if prefer_ipv6 {
        let table = TG_DC_V6;
        table[idx % table.len()]
    } else {
        let table = TG_DC_V4;
        table[idx % table.len()]
    }
}
