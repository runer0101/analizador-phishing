//! Static phishing link analyzer.
//!
//! The analyzer **never visits the URL**: it reads it as text and applies a fixed set of
//! rules that score the signals typical of fraud (plain HTTP, IP instead of a domain,
//! impersonated brands, typosquatting, URL shorteners, punycode, bait words).
//!
//! Standard library only: no external crates, no network, no DNS.

use std::fmt;

/// Risk level derived from the total score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Low,
    Medium,
    High,
}

impl Level {
    /// Thresholds of the activity: 5+ points is high, 3-4 medium, less than 3 low.
    pub fn from_score(score: u32) -> Self {
        match score {
            0..=2 => Level::Low,
            3..=4 => Level::Medium,
            _ => Level::High,
        }
    }

    /// Label shown in the terminal (Spanish: this is the presentation).
    pub fn label(self) -> &'static str {
        match self {
            Level::Low => "BAJO",
            Level::Medium => "MEDIO",
            Level::High => "ALTO",
        }
    }

    /// Stable token for JSON output.
    pub fn token(self) -> &'static str {
        match self {
            Level::Low => "low",
            Level::Medium => "medium",
            Level::High => "high",
        }
    }

    /// ANSI color: green, yellow, red.
    pub fn color(self) -> &'static str {
        match self {
            Level::Low => "\x1b[32m",
            Level::Medium => "\x1b[33m",
            Level::High => "\x1b[31m",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One detected signal, with its stable code and the points it contributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    pub code: &'static str,
    pub points: u32,
    pub detail: String,
}

/// Result of analyzing one link.
#[derive(Debug, Clone)]
pub struct Report {
    /// The link exactly as the user wrote it.
    pub input: String,
    /// Normalized host (lowercase, without `www.` and without a trailing dot).
    pub host: String,
    pub level: Level,
    pub score: u32,
    pub reasons: Vec<Reason>,
}

impl Report {
    /// Summary line: level, score and how many signals were found.
    pub fn summary(&self) -> String {
        let plural = if self.reasons.len() == 1 { "" } else { "es" };
        let points = if self.score == 1 { "pt" } else { "pts" };
        format!(
            "{} ({} {}, {} señal{})",
            self.level.label(),
            self.score,
            points,
            self.reasons.len(),
            plural
        )
    }

    /// Hand written JSON serialization (no serde).
    pub fn to_json(&self) -> String {
        let reasons: Vec<String> = self
            .reasons
            .iter()
            .map(|r| {
                format!(
                    "{{\"code\":{},\"points\":{},\"detail\":{}}}",
                    json_string(r.code),
                    r.points,
                    json_string(&r.detail)
                )
            })
            .collect();
        format!(
            "{{\"url\":{},\"host\":{},\"level\":{},\"score\":{},\"reasons\":[{}]}}",
            json_string(&self.input),
            json_string(&self.host),
            json_string(self.level.token()),
            self.score,
            reasons.join(",")
        )
    }
}

/// Escapes a string into a JSON literal.
pub fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A link taken apart by hand: the `url` crate is not used so the build needs no network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub userinfo: Option<String>,
    pub host: String,
    pub port: Option<String>,
    pub path: String,
    pub query: String,
}

impl ParsedUrl {
    /// Splits a URL into its parts. A missing scheme is assumed to be `http`.
    pub fn parse(input: &str) -> ParsedUrl {
        let trimmed = input.trim();
        let (scheme, rest) = match trimmed.find("://") {
            Some(i) => (trimmed[..i].to_ascii_lowercase(), &trimmed[i + 3..]),
            None => ("http".to_string(), trimmed),
        };

        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        let tail = &rest[authority_end..];

        let (userinfo, host_port) = match authority.rsplit_once('@') {
            Some((user, host)) => (Some(user.to_string()), host),
            None => (None, authority),
        };

        let (host_raw, port) = split_host_port(host_port);
        let host = normalize_host(&host_raw);

        let without_fragment = tail.split('#').next().unwrap_or("");
        let (path, query) = match without_fragment.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (without_fragment.to_string(), String::new()),
        };

        ParsedUrl {
            scheme,
            userinfo,
            host,
            port,
            path,
            query,
        }
    }
}

fn split_host_port(host_port: &str) -> (String, Option<String>) {
    if let Some(rest) = host_port.strip_prefix('[') {
        // IPv6 host in brackets: [::1]:2222
        return match rest.split_once(']') {
            Some((host, after)) => {
                let port = after.strip_prefix(':').map(|p| p.to_string());
                (format!("[{}]", host), port)
            }
            None => (host_port.to_string(), None),
        };
    }
    match host_port.split_once(':') {
        Some((host, port)) => (host.to_string(), Some(port.to_string())),
        None => (host_port.to_string(), None),
    }
}

/// Lowercase, without a trailing dot and without the `www.` prefix.
pub fn normalize_host(host: &str) -> String {
    let mut value = host.trim().to_ascii_lowercase();
    if value.ends_with('.') {
        value.pop();
    }
    if let Some(rest) = value.strip_prefix("www.") {
        value = rest.to_string();
    }
    value
}

/// Known brands and their official domain.
pub const BRANDS: &[(&str, &str)] = &[
    ("paypal", "paypal.com"),
    ("google", "google.com"),
    ("facebook", "facebook.com"),
    ("whatsapp", "whatsapp.com"),
    ("microsoft", "microsoft.com"),
    ("bancounion", "bancounion.com.bo"),
    ("bnb", "bnb.com.bo"),
];

/// Shorteners that hide the real destination.
pub const SHORTENERS: &[&str] = &[
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "ow.ly",
    "buff.ly",
    "rebrand.ly",
];

/// Endings that are cheap and therefore common in fraud.
pub const SUSPICIOUS_TLDS: &[&str] = &[
    ".xyz", ".top", ".tk", ".click", ".zip", ".icu", ".buzz", ".link", ".work", ".rest",
];

/// Bait words used to hook the victim.
pub const HOOK_WORDS: &[&str] = &[
    "login",
    "signin",
    "sign-in",
    "verify",
    "verificar",
    "verification",
    "secure",
    "seguridad",
    "update",
    "actualizar",
    "confirm",
    "confirmar",
    "banco",
    "clave",
    "password",
    "contrasena",
    "contraseña",
    "cuenta",
    "acceso",
    "recovery",
    "recuperar",
    "bloqueo",
    "suspended",
    "unusual",
];

/// Analyzes a link and returns its verdict.
pub fn analyze(input: &str) -> Report {
    let parsed = ParsedUrl::parse(input);
    let host = parsed.host.clone();
    let host_lower = host.to_ascii_lowercase();
    let url_lower =
        format!("{} {} {}", parsed.host, parsed.path, parsed.query).to_ascii_lowercase();
    let is_ip = is_ip_literal(&host);

    let mut reasons: Vec<Reason> = Vec::new();

    if parsed.scheme != "https" {
        reasons.push(Reason {
            code: "no_https",
            points: 1,
            detail: "No usa HTTPS: el tráfico puede interceptarse".to_string(),
        });
    }

    if is_ip {
        reasons.push(Reason {
            code: "ip_host",
            points: 2,
            detail: "Usa una dirección IP en vez de un dominio con nombre".to_string(),
        });
    }

    if parsed.userinfo.is_some() {
        reasons.push(Reason {
            code: "userinfo",
            points: 2,
            detail: "Contiene «@»: el dominio real queda escondido detrás".to_string(),
        });
    }

    if !is_ip && label_count(&host_lower) >= 4 {
        reasons.push(Reason {
            code: "deep_subdomain",
            points: 1,
            detail: "Demasiados subdominios: el dominio real está al final".to_string(),
        });
    }

    if host_lower.contains("xn--") {
        reasons.push(Reason {
            code: "punycode",
            points: 2,
            detail: "Punycode: posibles letras camufladas".to_string(),
        });
    }

    if is_shortener(&host_lower) {
        reasons.push(Reason {
            code: "shortener",
            points: 2,
            detail: "Link acortado: el destino real está oculto".to_string(),
        });
    }

    if has_suspicious_tld(&host_lower) {
        reasons.push(Reason {
            code: "suspicious_tld",
            points: 1,
            detail: "Terminación poco confiable".to_string(),
        });
    }

    if !is_ip && hyphen_count(&host_lower) >= 3 {
        reasons.push(Reason {
            code: "hyphen_chain",
            points: 1,
            detail: "Muchos guiones en el dominio: patrón habitual de suplantación".to_string(),
        });
    }

    if let Some(word) = first_hook_word(&url_lower) {
        reasons.push(Reason {
            code: "hook_words",
            points: 1,
            detail: format!("Palabra de gancho: «{word}»"),
        });
    }

    for (name, official) in BRANDS {
        if host_lower == *official || host_lower.ends_with(&format!(".{official}")) {
            break; // Official site: no brand rule applies.
        }
        if uses_brand_token(&host_lower, name) {
            reasons.push(Reason {
                code: "brand_impersonation",
                points: 3,
                detail: format!("Usa el nombre de {name} pero no es el sitio oficial ({official})"),
            });
            break;
        }
        if leet_normalize(&host_lower).contains(name) {
            reasons.push(Reason {
                code: "typosquat",
                points: 3,
                detail: format!("Imita a {official} (typosquatting)"),
            });
            break;
        }
    }

    let score: u32 = reasons.iter().map(|r| r.points).sum();
    let level = Level::from_score(score);

    Report {
        input: input.trim().to_string(),
        host,
        level,
        score,
        reasons,
    }
}

/// `true` when the host is a literal IPv4 or IPv6 address.
pub fn is_ip_literal(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.contains(':') {
        return true; // IPv6
    }
    let parts: Vec<&str> = bare.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.parse::<u8>().is_ok())
}

/// Number of domain labels (`a.b.c.d` is 4).
pub fn label_count(host: &str) -> usize {
    host.split('.').filter(|p| !p.is_empty()).count()
}

/// Number of hyphens in the host.
pub fn hyphen_count(host: &str) -> usize {
    host.matches('-').count()
}

/// `true` when the host is a known shortener.
pub fn is_shortener(host: &str) -> bool {
    SHORTENERS
        .iter()
        .any(|s| host == *s || host.ends_with(&format!("/{s}")))
}

/// `true` when the domain ends with an untrustworthy ending.
pub fn has_suspicious_tld(host: &str) -> bool {
    SUSPICIOUS_TLDS.iter().any(|tld| host.ends_with(tld))
}

/// First bait word found in the text (already lowercased).
pub fn first_hook_word(text: &str) -> Option<&'static str> {
    HOOK_WORDS.iter().find(|word| text.contains(*word)).copied()
}

/// `true` when the host uses the brand name in one of its labels.
pub fn uses_brand_token(host: &str, name: &str) -> bool {
    host.split('.')
        .any(|label| label == name || label.starts_with(name))
}

/// Turns imitated digits into letters: `paypa1` -> `paypal`.
pub fn leet_normalize(host: &str) -> String {
    host.chars()
        .map(|c| match c {
            '0' => 'o',
            '1' => 'l',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            other => other,
        })
        .collect()
}

/// A demonstration link with its expected verdict and the note explained to the audience.
pub struct DemoCase {
    pub url: &'static str,
    pub expected: Level,
    pub note: &'static str,
}

/// The five links of the demonstration.
pub const DEMO_CASES: &[DemoCase] = &[
    DemoCase {
        url: "http://paypa1.com/login/verify",
        expected: Level::High,
        note: "El «1» imita la «l» de PayPal: typosquatting.",
    },
    DemoCase {
        url: "http://paypal.secure-verify-login.com/account",
        expected: Level::High,
        note: "Usa el nombre de PayPal pero el dominio real termina en .com.",
    },
    DemoCase {
        url: "http://192.168.56.101/wp-login.php",
        expected: Level::Medium,
        note: "Login de WordPress servido desde una IP cruda.",
    },
    DemoCase {
        url: "https://www.bancounion.com.bo/verificacion-clave",
        expected: Level::Low,
        note: "Sitio real: el analizador lo marca por las palabras de la ruta (falso positivo).",
    },
    DemoCase {
        url: "https://www.google.com",
        expected: Level::Low,
        note: "Sitio legítimo: ninguna señal sospechosa.",
    },
];

/// The browser demo compiles this library to WebAssembly; the boundary lives in `wasm.rs`.
#[cfg(target_arch = "wasm32")]
mod wasm;

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(report: &Report) -> Vec<&str> {
        report.reasons.iter().map(|r| r.code).collect()
    }

    fn points_of(report: &Report, code: &str) -> u32 {
        report
            .reasons
            .iter()
            .find(|r| r.code == code)
            .unwrap_or_else(|| panic!("falta la señal {code}"))
            .points
    }

    #[test]
    fn detects_missing_https() {
        let report = analyze("http://ejemplo.com");
        assert_eq!(report.reasons[0].code, "no_https");
        assert_eq!(report.reasons[0].points, 1);
    }

    #[test]
    fn https_has_no_https_reason() {
        let report = analyze("https://ejemplo.com");
        assert!(!codes(&report).contains(&"no_https"));
    }

    #[test]
    fn detects_ip_host() {
        let report = analyze("https://192.168.1.10/login");
        assert!(codes(&report).contains(&"ip_host"));
        assert_eq!(points_of(&report, "ip_host"), 2);
    }

    #[test]
    fn ip_host_is_not_deep_subdomain() {
        let report = analyze("https://192.168.1.10/");
        assert!(!codes(&report).contains(&"deep_subdomain"));
    }

    #[test]
    fn detects_userinfo_trick() {
        let report = analyze("http://banco.com@banco-falso.com/");
        assert!(codes(&report).contains(&"userinfo"));
        assert_eq!(points_of(&report, "userinfo"), 2);
    }

    #[test]
    fn userinfo_keeps_the_real_host() {
        let parsed = ParsedUrl::parse("http://banco.com@banco-falso.com/x");
        assert_eq!(parsed.userinfo.as_deref(), Some("banco.com"));
        assert_eq!(parsed.host, "banco-falso.com");
    }

    #[test]
    fn detects_deep_subdomain() {
        let report = analyze("https://login.banco.com.seguro.servidor.com/");
        assert!(codes(&report).contains(&"deep_subdomain"));
    }

    #[test]
    fn detects_punycode() {
        let report = analyze("https://xn--80ak6aa92e.com/");
        assert!(codes(&report).contains(&"punycode"));
        assert_eq!(points_of(&report, "punycode"), 2);
    }

    #[test]
    fn detects_shortener() {
        let report = analyze("http://bit.ly/3xAbCdE");
        assert!(codes(&report).contains(&"shortener"));
        assert_eq!(points_of(&report, "shortener"), 2);
    }

    #[test]
    fn detects_suspicious_tld() {
        let report = analyze("https://banco-verificacion.xyz/");
        assert!(codes(&report).contains(&"suspicious_tld"));
    }

    #[test]
    fn detects_hyphen_chain() {
        let report = analyze("https://banco-seguro-verificacion-cuenta.com/");
        assert!(codes(&report).contains(&"hyphen_chain"));
    }

    #[test]
    fn detects_hook_word() {
        let report = analyze("https://sitio-real.com/login");
        assert!(codes(&report).contains(&"hook_words"));
    }

    #[test]
    fn detects_brand_impersonation() {
        let report = analyze("http://paypal.secure-verify-login.com/account");
        assert!(codes(&report).contains(&"brand_impersonation"));
        assert_eq!(points_of(&report, "brand_impersonation"), 3);
    }

    #[test]
    fn detects_typosquat() {
        let report = analyze("http://paypa1.com/login/verify");
        assert!(codes(&report).contains(&"typosquat"));
        assert_eq!(points_of(&report, "typosquat"), 3);
    }

    #[test]
    fn official_brand_is_clean() {
        let report = analyze("https://www.paypal.com/");
        assert!(!codes(&report).contains(&"brand_impersonation"));
        assert!(!codes(&report).contains(&"typosquat"));
    }

    #[test]
    fn brand_inside_an_official_domain_is_clean() {
        let report = analyze("https://www.bancounion.com.bo/");
        assert!(!codes(&report).contains(&"brand_impersonation"));
        assert!(!codes(&report).contains(&"typosquat"));
    }

    #[test]
    fn level_thresholds() {
        assert_eq!(Level::from_score(0), Level::Low);
        assert_eq!(Level::from_score(2), Level::Low);
        assert_eq!(Level::from_score(3), Level::Medium);
        assert_eq!(Level::from_score(4), Level::Medium);
        assert_eq!(Level::from_score(5), Level::High);
        assert_eq!(Level::from_score(9), Level::High);
    }

    #[test]
    fn score_is_the_sum_of_the_signals() {
        let report = analyze("http://paypa1.com/login/verify");
        let sum: u32 = report.reasons.iter().map(|r| r.points).sum();
        assert_eq!(report.score, sum);
        assert_eq!(report.level, Level::High);
    }

    #[test]
    fn parses_missing_scheme_as_http() {
        let parsed = ParsedUrl::parse("ejemplo.com/hola");
        assert_eq!(parsed.scheme, "http");
        assert_eq!(parsed.host, "ejemplo.com");
        assert_eq!(parsed.path, "/hola");
    }

    #[test]
    fn parses_port_and_query() {
        let parsed = ParsedUrl::parse("http://ejemplo.com:8080/a/b?x=1&y=2");
        assert_eq!(parsed.port.as_deref(), Some("8080"));
        assert_eq!(parsed.query, "x=1&y=2");
    }

    #[test]
    fn strips_www_and_trailing_dot() {
        assert_eq!(normalize_host("WWW.Ejemplo.COM."), "ejemplo.com");
    }

    #[test]
    fn detects_ipv6_literal() {
        assert!(is_ip_literal("[::1]"));
        assert!(is_ip_literal("192.168.0.1"));
        assert!(!is_ip_literal("ejemplo.com"));
    }

    #[test]
    fn json_escapes_quotes() {
        assert_eq!(json_string("a\"b\\c\nd"), r#""a\"b\\c\nd""#);
    }

    #[test]
    fn report_json_is_well_formed() {
        let json = analyze("http://paypa1.com/login/verify").to_json();
        assert!(json.starts_with('{'));
        assert!(json.ends_with('}'));
        assert!(json.contains("\"level\":\"high\""));
        assert!(json.contains("\"code\":\"typosquat\""));
    }

    #[test]
    fn demo_cases_match_expected_verdicts() {
        for case in DEMO_CASES {
            let report = analyze(case.url);
            assert_eq!(
                report.level, case.expected,
                "veredicto inesperado para {}: {:?}",
                case.url, report.reasons
            );
        }
    }
}
