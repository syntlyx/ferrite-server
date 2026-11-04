//! A configuration profile (`.mobileconfig`) that points an iPhone, iPad or
//! Mac at this box's encrypted DNS under a device's own client ID. iOS has no
//! field to type a DNS over HTTPS address into; a profile is the way in.
//! It is unsigned, so the device calls it unverified — it installs all the
//! same.

use ring::digest;

/// A UUID that stays the same for the same box, device and part: installing
/// a fresh copy replaces the old profile instead of adding a second one.
fn stable_uuid(parts: &[&str]) -> String {
    let d = digest::digest(&digest::SHA256, parts.join("/").as_bytes());
    let mut b = [0u8; 16];
    b.copy_from_slice(&d.as_ref()[..16]);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode_upper(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// How the device reaches us: over HTTPS (the ID in the path, which works
/// without a wildcard certificate) when that is on, else over TLS.
pub(crate) fn mobileconfig(
    hostname: &str,
    device: &str,
    doh_port: u16,
    dot_port: u16,
) -> Option<String> {
    let settings = if doh_port != 0 {
        let url = if doh_port == 443 {
            format!("https://{hostname}/dns-query/{device}")
        } else {
            format!("https://{hostname}:{doh_port}/dns-query/{device}")
        };
        format!(
            "<key>DNSProtocol</key><string>HTTPS</string>\n\t\t\t\t<key>ServerURL</key><string>{}</string>",
            xml(&url)
        )
    } else if dot_port == 853 {
        format!(
            "<key>DNSProtocol</key><string>TLS</string>\n\t\t\t\t<key>ServerName</key><string>{}</string>",
            xml(&format!("{device}.{hostname}"))
        )
    } else {
        // Apple's TLS setting has no port: only 853 works.
        return None;
    };
    let id = format!("me.ferrite.encrypted-dns.{hostname}.{device}");
    let name = format!("ferrite — {device}");
    let about = format!(
        "Encrypted DNS through ferrite at {hostname}, as the device \u{201c}{device}\u{201d}."
    );
    Some(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>DNSSettings</key>
			<dict>
				{settings}
			</dict>
			<key>PayloadDescription</key><string>{about}</string>
			<key>PayloadDisplayName</key><string>{name}</string>
			<key>PayloadIdentifier</key><string>{id}.dns</string>
			<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
			<key>PayloadUUID</key><string>{inner}</string>
			<key>PayloadVersion</key><integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key><string>{about}</string>
	<key>PayloadDisplayName</key><string>{name}</string>
	<key>PayloadIdentifier</key><string>{id}</string>
	<key>PayloadRemovalDisallowed</key><false/>
	<key>PayloadType</key><string>Configuration</string>
	<key>PayloadUUID</key><string>{outer}</string>
	<key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
"#,
        about = xml(&about),
        name = xml(&name),
        id = xml(&id),
        inner = stable_uuid(&[hostname, device, "dns"]),
        outer = stable_uuid(&[hostname, device, "profile"]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_carries_the_device_in_its_address() {
        let p = mobileconfig("dns.example.com", "iphone", 443, 853).unwrap();
        assert!(p.contains("<string>https://dns.example.com/dns-query/iphone</string>"));
        assert!(p.contains("com.apple.dnsSettings.managed"));
        assert!(p.contains("<string>HTTPS</string>"));

        let p = mobileconfig("dns.example.com", "mac", 8443, 853).unwrap();
        assert!(p.contains("https://dns.example.com:8443/dns-query/mac"));

        let p = mobileconfig("dns.example.com", "ipad", 0, 853).unwrap();
        assert!(p.contains("<string>TLS</string>"));
        assert!(p.contains("<string>ipad.dns.example.com</string>"));

        assert!(mobileconfig("dns.example.com", "ipad", 0, 8853).is_none());
    }

    #[test]
    fn the_same_device_gets_the_same_identity() {
        let a = stable_uuid(&["dns.example.com", "iphone", "profile"]);
        assert_eq!(a, stable_uuid(&["dns.example.com", "iphone", "profile"]));
        assert_ne!(a, stable_uuid(&["dns.example.com", "ipad", "profile"]));
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
    }
}
