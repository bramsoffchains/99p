//! Host normalisation and matching (SPEC §6.6). No public-suffix list: an
//! entry host matches itself and its subdomains, nothing else.

use crate::error::{Error, Result};
use crate::model::Entry;

/// Normalises a URL or bare host: lowercase ASCII, no scheme, userinfo, port,
/// path or trailing dot. Non-ASCII hosts must arrive in punycode (`xn--`),
/// as browsers report them.
pub fn normalize(input: &str) -> Result<String> {
    let mut s = input.trim();
    if let Some(i) = s.find("://") {
        s = &s[i + 3..];
    }
    // Browsers treat `\` like `/` in special URLs.
    let end = s.find(['/', '\\', '?', '#']).unwrap_or(s.len());
    s = &s[..end];
    if let Some(i) = s.rfind('@') {
        s = &s[i + 1..];
    }
    let host = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal, kept with brackets.
        let close = rest.find(']').ok_or(Error::Invalid("bad IPv6 host"))?;
        let ip = &rest[..close];
        if ip.is_empty()
            || !ip
                .bytes()
                .all(|c| c.is_ascii_hexdigit() || c == b':' || c == b'.')
        {
            return Err(Error::Invalid("bad IPv6 host"));
        }
        return Ok(format!("[{}]", ip.to_ascii_lowercase()));
    } else {
        s.split(':').next().unwrap_or("")
    };
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(Error::Invalid("empty or too long host"));
    }
    for label in host.split('.') {
        let ok = !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !ok {
            return Err(Error::Invalid(
                "host has an invalid label (non-ASCII must be punycode)",
            ));
        }
    }
    Ok(host)
}

fn strip_www(h: &str) -> &str {
    h.strip_prefix("www.")
        .filter(|r| r.contains('.'))
        .unwrap_or(h)
}

/// Match rank of normalised request host `request` against entry host
/// `entry`: 0 exact, 1 subdomain, `None` no match. A leading `www.` is
/// ignored on both sides.
pub fn match_rank(request: &str, entry: &str) -> Option<u8> {
    let (r, e) = (strip_www(request), strip_www(entry));
    if r == e {
        Some(0)
    } else if r.len() > e.len() && r.ends_with(e) && r.as_bytes()[r.len() - e.len() - 1] == b'.' {
        Some(1)
    } else {
        None
    }
}

/// Indices of live entries matching `request_host`, best rank first, then by name.
pub fn matching_entries(entries: &[Entry], request_host: &str) -> Vec<(usize, u8)> {
    let mut out: Vec<(usize, u8)> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.deleted)
        .filter_map(|(i, e)| {
            e.hosts
                .iter()
                .filter_map(|h| match_rank(request_host, h))
                .min()
                .map(|r| (i, r))
        })
        .collect();
    out.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then_with(|| entries[a.0].name.cmp(&entries[b.0].name))
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntryKind;

    #[test]
    fn normalizes() {
        let cases = [
            ("https://GitHub.com/login?x=1", "github.com"),
            ("github.com", "github.com"),
            (
                "http://user:pw@App.Example.com:8443/path",
                "app.example.com",
            ),
            ("example.com.", "example.com"),
            ("https://evil.net\\@github.com/", "evil.net"),
            ("https://github.com@evil.net/", "evil.net"),
            ("https://evil.net/github.com", "evil.net"),
            ("xn--pple-43d.com", "xn--pple-43d.com"),
            ("http://[::1]:8080/", "[::1]"),
            ("192.168.1.1:80", "192.168.1.1"),
            ("  WWW.Example.COM  ", "www.example.com"),
        ];
        for (input, want) in cases {
            assert_eq!(normalize(input).unwrap(), want, "{input}");
        }
        for bad in [
            "",
            "https://",
            "аpple.com",
            "exa mple.com",
            "a..b",
            "-a.com",
            "github.com%2eevil.net",
        ] {
            assert!(normalize(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ranks() {
        assert_eq!(match_rank("github.com", "github.com"), Some(0));
        assert_eq!(match_rank("www.github.com", "github.com"), Some(0));
        assert_eq!(match_rank("github.com", "www.github.com"), Some(0));
        assert_eq!(match_rank("gist.github.com", "github.com"), Some(1));
        assert_eq!(match_rank("a.b.github.com", "github.com"), Some(1));
        // An entry for a subdomain does not match its parent or siblings.
        assert_eq!(match_rank("github.com", "gist.github.com"), None);
        assert_eq!(match_rank("api.github.com", "gist.github.com"), None);
    }

    #[test]
    fn phishing_lookalikes_do_not_match() {
        let lookalikes = [
            "github.com.evil.net",
            "evilgithub.com",
            "evil-github.com",
            "githubb.com",
            "github.co",
            "githuh.com",
            "xn--github-xya.com",
            "github.com-login.net",
            "www.github.com.evil.net",
            "com",
        ];
        for h in lookalikes {
            assert_eq!(match_rank(h, "github.com"), None, "{h}");
        }
        // Lookalikes delivered as URLs normalise to the attacker's host.
        for url in [
            "https://github.com@evil.net",
            "https://evil.net/github.com",
            "https://evil.net\\github.com",
        ] {
            assert_eq!(
                match_rank(&normalize(url).unwrap(), "github.com"),
                None,
                "{url}"
            );
        }
    }

    #[test]
    fn ranks_entries() {
        let e = |name: &str, host: &str, deleted| Entry {
            id: 1,
            kind: EntryKind::Login,
            name: name.into(),
            hosts: vec![host.into()],
            created_at: 0,
            updated_at: 0,
            deleted,
            fields: vec![],
            extra: vec![],
        };
        let entries = vec![
            e("b parent", "example.com", false),
            e("exact", "app.example.com", false),
            e("a parent", "example.com", false),
            e("gone", "app.example.com", true),
            e("other", "example.org", false),
        ];
        assert_eq!(
            matching_entries(&entries, "app.example.com"),
            vec![(1, 0), (2, 1), (0, 1)]
        );
    }
}
