//! Default paths for Windows known folders.

pub fn known_folder_path(guid: &str) -> Option<&'static str> {
    match guid.trim_matches(['{', '}']).to_ascii_uppercase().as_str() {
        "5CD7AEE2-2219-4A67-B85D-6C9CE15660CB" => Some(r"%LocalAppData%\Programs"),
        "BCBD3057-CA5C-4622-B42D-BC56DB0AE516" => Some(r"%LocalAppData%\Programs\Common"),
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091" => Some("%LocalAppData%"),
        "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D" => Some("%AppData%"),
        "62AB5D82-FDC1-4DC3-A9DD-070D1D495D97" => Some("%ProgramData%"),
        "5E6C858F-0E22-4760-9AFE-EA3317B67173" => Some("%UserProfile%"),
        _ => None,
    }
}
