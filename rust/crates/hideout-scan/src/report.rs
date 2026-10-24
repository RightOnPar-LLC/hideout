//! The stand-alone HTML report: the repo's report.html template with the scan's JSON
//! dropped in. Names and paths come from the PC being scanned - malware picks them - so
//! everything that could close the <script> tag or start markup is escaped, and the page
//! itself only ever renders with textContent.

/// The template, compiled in from the repo root so there is exactly one copy of it.
pub const TEMPLATE: &str = include_str!("../../../../report.html");
const SLOT: &str = "/*__HIDEOUT_DATA__*/null";

/// JSON made safe to sit inside a <script> element.
pub fn script_safe_json(json: &str) -> String {
    json.replace('<', "\\u003c").replace('>', "\\u003e").replace('&', "\\u0026")
}

pub fn render(compact_json: &str) -> String {
    TEMPLATE.replace(SLOT, &script_safe_json(compact_json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_has_the_slot_and_no_network() {
        assert!(TEMPLATE.contains(SLOT));
        assert!(TEMPLATE.contains("default-src 'none'"));
        assert!(!TEMPLATE.contains("http://") && !TEMPLATE.contains("https://"));
    }

    #[test]
    fn hostile_names_cannot_inject_markup() {
        let html = render(r#"{"name":"</script><img src=x onerror=alert(1)>&amp;"}"#);
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("</script><img"));
        assert!(html.contains("\\u003cimg src=x"));
        assert!(!html.contains(SLOT));
    }
}
