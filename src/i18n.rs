// Internationalization helpers
// 国际化辅助工具

use std::sync::{OnceLock, RwLock};

/// Supported languages
/// 支持的语言
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Language {
    English,
    Chinese,
}

impl Default for Language {
    fn default() -> Self {
        Language::English
    }
}

static LANGUAGE: OnceLock<RwLock<Language>> = OnceLock::new();

fn language_lock() -> &'static RwLock<Language> {
    LANGUAGE.get_or_init(|| RwLock::new(Language::default()))
}

/// Set global language
/// 设置全局语言
pub fn set_language(language: Language) {
    let mut guard = language_lock()
        .write()
        .expect("language lock poisoned");
    *guard = language;
}

/// Get current language
/// 获取当前语言
pub fn language() -> Language {
    *language_lock()
        .read()
        .expect("language lock poisoned")
}

/// Returns true if current language is Chinese
/// 当前语言是否为中文
pub fn is_zh() -> bool {
    matches!(language(), Language::Chinese)
}

/// Parse language string
/// 解析语言字符串
pub fn parse_language(input: &str) -> Option<Language> {
    let trimmed = input.trim().trim_start_matches('-').to_lowercase();
    match trimmed.as_str() {
        "en" | "en-us" | "en_us" | "english" => Some(Language::English),
        "zh" | "zh-cn" | "zh_cn" | "zh-hans" | "chinese" | "cn" => {
            Some(Language::Chinese)
        }
        _ => None,
    }
}

/// Select a static string by language
/// 根据语言选择静态字符串
pub fn t<'a>(en: &'a str, zh: &'a str) -> &'a str {
    if is_zh() { zh } else { en }
}
