use std::collections::HashMap;

use camino::Utf8Path;
use winget_types::installer::{Architecture, Installer, Scope, VALID_FILE_EXTENSIONS};

fn locale_score(previous_installer: &Installer, new_installer: &Installer) -> f64 {
    let Some(previous_locale) = previous_installer.locale.as_ref() else {
        return 0.0;
    };

    // Compare directly if installer analysis can detect a locale
    if let Some(new_locale) = new_installer.locale.as_ref() {
        if new_locale == previous_locale {
            return 3.0;
        }
        if new_locale.language() == previous_locale.language() {
            return 2.0;
        }
        return 0.0;
    }

    // Otherwise fall back to inferring locale from the URL
    let url = new_installer.url.as_str().to_ascii_lowercase();
    let url_tokens: Vec<&str> = url
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    let has_token = |s: &str| url_tokens.contains(&s.to_ascii_lowercase().as_str());
    let mut score = 0.0;

    if has_token(previous_locale.language().as_str()) {
        score += 2.0;
    }
    if let Some(script) = previous_locale.script()
        && has_token(script.as_str())
    {
        score += 1.0;
    }
    if let Some(region) = previous_locale.region()
        && has_token(region.as_str())
    {
        score += 1.0;
    }
    score
}

fn url_similarity_score(previous_url: &str, new_url: &str) -> f64 {
    let previous_url = previous_url.to_ascii_lowercase();
    let new_url = new_url.to_ascii_lowercase();

    strsim::jaro_winkler(&previous_url, &new_url) * 3.0
}

pub fn match_installers(
    previous_installers: Vec<Installer>,
    new_installers: &[Installer],
) -> HashMap<Installer, Installer> {
    let found_architectures = new_installers
        .iter()
        .filter_map(|installer| {
            let url = &installer.url;
            Architecture::from_url(url.as_str()).map(|architecture| (url, architecture))
        })
        .collect::<HashMap<_, _>>();

    let found_scopes = new_installers
        .iter()
        .filter_map(|installer| {
            let url = &installer.url;
            Scope::find_in(url.as_str()).map(|scope| (url, scope))
        })
        .collect::<HashMap<_, _>>();

    previous_installers
        .into_iter()
        .map(|previous_installer| {
            let mut max_score = 0.0;
            let mut best_match = None;

            for new_installer in new_installers {
                let installer_url = &new_installer.url;
                let mut score = 0.0;
                if new_installer.architecture == previous_installer.architecture {
                    score += 1.0;
                }
                if found_architectures.get(installer_url) == Some(&previous_installer.architecture)
                {
                    score += 1.0;
                }
                if new_installer.r#type == previous_installer.r#type {
                    score += 3.0;
                }
                if new_installer.nested_installer_type == previous_installer.nested_installer_type {
                    score += 3.0;
                }
                if new_installer.scope == previous_installer.scope {
                    score += 1.0;
                }
                score += locale_score(&previous_installer, new_installer);
                score += url_similarity_score(
                    previous_installer.url.as_str(),
                    new_installer.url.as_str(),
                );

                let new_extension = Utf8Path::new(new_installer.url.as_str())
                    .extension()
                    .filter(|extension| VALID_FILE_EXTENSIONS.contains(extension))
                    .unwrap_or_default();
                let previous_extension = Utf8Path::new(previous_installer.url.as_str())
                    .extension()
                    .filter(|extension| VALID_FILE_EXTENSIONS.contains(extension))
                    .unwrap_or_default();
                if new_extension != previous_extension {
                    score = 0.0;
                }

                let is_new_architecture = !found_architectures.is_empty()
                    && !found_architectures.contains_key(installer_url);
                let is_new_scope =
                    !found_scopes.is_empty() && !found_scopes.contains_key(installer_url);

                if score > max_score
                    || (score.total_cmp(&max_score).is_eq()
                        && (is_new_architecture || is_new_scope))
                    || best_match.is_none()
                {
                    max_score = score;
                    best_match = Some(new_installer);
                }
            }

            (previous_installer, best_match.cloned().unwrap())
        })
        .collect::<HashMap<_, _>>()
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, str::FromStr};

    use rstest::rstest;
    use winget_types::{
        installer::{Architecture, Installer, Scope},
        url::DecodedUrl,
    };

    use crate::match_installers::match_installers;

    #[test]
    fn test_vscodium() {
        let installer_x86 = Installer {
            architecture: Architecture::X86,
            url: DecodedUrl::from_str("https://www.example.com/file-x86.exe").unwrap(),
            ..Installer::default()
        };
        let installer_user_x86 = Installer {
            scope: Some(Scope::User),
            url: DecodedUrl::from_str("https://www.example.com/fileUser-x86.exe").unwrap(),
            ..installer_x86.clone()
        };
        let installer_x64 = Installer {
            architecture: Architecture::X64,
            url: DecodedUrl::from_str("https://www.example.com/file-x64.exe").unwrap(),
            ..Installer::default()
        };
        let installer_user_x64 = Installer {
            scope: Some(Scope::User),
            url: DecodedUrl::from_str("https://www.example.com/fileUser-x64.exe").unwrap(),
            ..installer_x64.clone()
        };
        let previous_machine_x86 = Installer {
            scope: Some(Scope::Machine),
            ..installer_x86.clone()
        };
        let previous_machine_x64 = Installer {
            scope: Some(Scope::Machine),
            ..installer_x64.clone()
        };
        let previous_installers = vec![
            installer_user_x86.clone(),
            previous_machine_x86.clone(),
            installer_user_x64.clone(),
            previous_machine_x64.clone(),
        ];
        let new_installers = vec![
            installer_user_x86.clone(),
            installer_x86.clone(),
            installer_user_x64.clone(),
            installer_x64.clone(),
        ];
        let expected = HashMap::from([
            (installer_user_x86.clone(), installer_user_x86),
            (previous_machine_x86, installer_x86),
            (installer_user_x64.clone(), installer_user_x64),
            (previous_machine_x64, installer_x64),
        ]);
        assert_eq!(
            match_installers(previous_installers, &new_installers),
            expected
        );
    }

    #[rstest]
    #[case::exact_english(
        "en-US",
        "https://www.example.com/downloads/installer_2eae0ed.exe",
        "en-US",
        "https://www.example.com/downloads/installer_419b1e8.exe",
        "fr-FR",
        "https://www.example.com/downloads/installer_aba97fd.exe"
    )]
    #[case::exact_french(
        "fr-FR",
        "https://www.example.com/downloads/installer_8a4a542.exe",
        "fr-FR",
        "https://www.example.com/downloads/installer_aba97fd.exe",
        "en-US",
        "https://www.example.com/downloads/installer_419b1e8.exe"
    )]
    #[case::language_only_english(
        "en-US",
        "https://www.example.com/downloads/installer_2eae0ed.exe",
        "en-GB",
        "https://www.example.com/downloads/installer_419b1e8.exe",
        "fr-CA",
        "https://www.example.com/downloads/installer_aba97fd.exe"
    )]
    #[case::language_only_french(
        "fr-FR",
        "https://www.example.com/downloads/installer_8a4a542.exe",
        "fr-CA",
        "https://www.example.com/downloads/installer_aba97fd.exe",
        "en-GB",
        "https://www.example.com/downloads/installer_419b1e8.exe"
    )]
    fn matches_locales_by_direct_analysis(
        #[case] previous_locale: &str,
        #[case] previous_url: &str,
        #[case] expected_locale: &str,
        #[case] expected_url: &str,
        #[case] competing_locale: &str,
        #[case] competing_url: &str,
    ) {
        let previous_installer = Installer {
            locale: Some(previous_locale.parse().unwrap()),
            url: DecodedUrl::from_str(previous_url).unwrap(),
            ..Installer::default()
        };
        let expected_installer = Installer {
            locale: Some(expected_locale.parse().unwrap()),
            url: DecodedUrl::from_str(expected_url).unwrap(),
            ..Installer::default()
        };
        let competing_installer = Installer {
            locale: Some(competing_locale.parse().unwrap()),
            url: DecodedUrl::from_str(competing_url).unwrap(),
            ..Installer::default()
        };

        assert_eq!(
            match_installers(
                vec![previous_installer.clone()],
                &[competing_installer, expected_installer.clone()],
            ),
            HashMap::from([(previous_installer, expected_installer)])
        );
    }

    #[rstest]
    #[case::icu_english(
        "en-US",
        "https://www.example.com/app-1.0.en-US.exe",
        "https://www.example.com/app-2.0.en-US.exe"
    )]
    #[case::icu_french(
        "fr-FR",
        "https://www.example.com/app-1.0.fr-FR.exe",
        "https://www.example.com/app-2.0.fr-FR.exe"
    )]
    #[case::icu_german(
        "de-DE",
        "https://www.example.com/app-1.0.de-DE.exe",
        "https://www.example.com/app-2.0.de.exe"
    )]
    #[case::icu_portuguese(
        "pt-BR",
        "https://www.example.com/app-1.0.pt-BR.exe",
        "https://www.example.com/app-2.0.pt-BR.exe"
    )]
    #[case::icu_simplified_chinese(
        "zh-CN",
        "https://www.example.com/app-1.0.zh.exe",
        "https://www.example.com/app-2.0.zh.exe"
    )]
    #[case::icu_traditional_chinese(
        "zh-TW",
        "https://www.example.com/app-1.0.zh-TW.exe",
        "https://www.example.com/app-2.0.zh-TW.exe"
    )]
    #[case::similarity_english(
        "en-GB",
        "https://www.example.com/downloads/app_2_8_English.exe",
        "https://www.example.com/downloads/app_2_9_English.exe"
    )]
    #[case::similarity_french(
        "fr-FR",
        "https://www.example.com/downloads/app_2_8_French.exe",
        "https://www.example.com/downloads/app_2_9_French.exe"
    )]
    #[case::similarity_italian(
        "it-IT",
        "https://www.example.com/downloads/app_2_8_Italian.exe",
        "https://www.example.com/downloads/app_2_9_Italian.exe"
    )]
    #[case::similarity_portuguese(
        "pt-PT",
        "https://www.example.com/downloads/app_2_8_Portuguese.exe",
        "https://www.example.com/downloads/app_2_9_Portuguese.exe"
    )]
    #[case::similarity_russian(
        "ru-RU",
        "https://www.example.com/downloads/app_2_8_Russian.exe",
        "https://www.example.com/downloads/app_2_9_Russian.exe"
    )]
    #[case::similarity_spanish(
        "es-AR",
        "https://www.example.com/downloads/app_2_8_Espanol.exe",
        "https://www.example.com/downloads/app_2_9_Espanol.exe"
    )]
    #[case::similarity_turkish(
        "tr-TR",
        "https://www.example.com/downloads/app_2_8_Turkish.exe",
        "https://www.example.com/downloads/app_2_9_Turkish.exe"
    )]
    #[case::similarity_german(
        "de-DE",
        "https://www.example.com/downloads/app_2_8_Deutsch.exe",
        "https://www.example.com/downloads/app_2_9_Deutsch.exe"
    )]
    #[case::similarity_simplified_chinese(
        "zh-CN",
        "https://www.example.com/downloads/app_2_8_SCN.exe",
        "https://www.example.com/downloads/app_2_9_SCN.exe"
    )]
    fn matches_locale_by_url(
        #[case] locale: &str,
        #[case] previous_url: &str,
        #[case] expected_url: &str,
    ) {
        let previous_installer = Installer {
            locale: Some(locale.parse().unwrap()),
            url: DecodedUrl::from_str(previous_url).unwrap(),
            ..Installer::default()
        };
        let expected_installer = Installer {
            url: DecodedUrl::from_str(expected_url).unwrap(),
            ..Installer::default()
        };
        let competing_installer = Installer {
            url: DecodedUrl::from_str("https://www.example.com/downloads/installer_419b1e8.exe")
                .unwrap(),
            ..Installer::default()
        };
        assert_eq!(
            match_installers(
                vec![previous_installer.clone()],
                &[competing_installer, expected_installer.clone()],
            ),
            HashMap::from([(previous_installer, expected_installer)])
        );
    }
}
