use std::{env, sync::LazyLock};

pub static CI: LazyLock<bool> =
    LazyLock::new(|| env::var("CI").is_ok_and(|ci| ci.parse() == Ok(true)));

pub static VHS: LazyLock<bool> =
    LazyLock::new(|| env::var("VHS").is_ok_and(|vhs| vhs.parse() == Ok(true)));

pub static EDITOR: LazyLock<Option<String>> = LazyLock::new(|| {
    ["KOMAC_EDITOR", "EDITOR"]
        .into_iter()
        .find_map(|key| env::var(key).ok().filter(|val| !val.is_empty()))
});
