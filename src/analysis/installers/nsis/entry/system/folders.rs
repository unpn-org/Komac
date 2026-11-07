//! Default paths for Windows known folders.

pub fn known_folder_path(guid: &str) -> Option<&'static str> {
    match guid.trim_matches(['{', '}']).to_ascii_uppercase().as_str() {
        "5CD7AEE2-2219-4A67-B85D-6C9CE15660CB" => Some(r"%LocalAppData%\Programs"),
        "BCBD3057-CA5C-4622-B42D-BC56DB0AE516" => Some(r"%LocalAppData%\Programs\Common"),
        _ => None,
    }
}
