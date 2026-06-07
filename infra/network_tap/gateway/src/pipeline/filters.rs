use crate::models::ArkimeSpi;

/// Returns `true` if the session is noise that should be dropped before
/// feature extraction. Checks ordered cheapest-first.
#[inline(always)]
pub fn is_noise(spi: &ArkimeSpi) -> bool {
    // Zero-byte sessions (keepalives, reset-only)
    if spi.by1 == 0 && spi.by2 == 0 {
        return true;
    }

    // UDP broadcast/multicast noise
    if spi.pr == 17 {
        if spi.p1 == 5353 || spi.p2 == 5353 { return true; }  // mDNS
        if spi.p1 == 1900 || spi.p2 == 1900 { return true; }  // SSDP
        if spi.p1 == 137 || spi.p2 == 137 { return true; }    // NetBIOS
        if spi.p1 == 138 || spi.p2 == 138 { return true; }
        if spi.p1 == 5355 || spi.p2 == 5355 { return true; }  // LLMNR
    }

    false
}
