use std::path::{Path, PathBuf};

use regex::Regex;

use super::report::{AuditFinding, AuditSeverity};

/// Static code/config scanner for security vulnerabilities in project files
pub struct FileScanner {
    base_dir: PathBuf,
}

struct ScanRule {
    id: &'static str,
    category: &'static str,
    severity: AuditSeverity,
    title: &'static str,
    description: &'static str,
    pattern: Regex,
    mitre: Option<&'static str>,
    recommendation: &'static str,
    extensions: &'static [&'static str],
}

impl FileScanner {
    pub fn new(base_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
        }
    }

    pub fn scan(&self) -> (Vec<AuditFinding>, usize) {
        let rules = self.build_rules();
        let mut findings = Vec::new();
        let mut files_scanned = 0;

        let scan_dirs = ["src", "fronted", "config", "scripts", "data"];
        for dir_name in scan_dirs {
            let dir = self.base_dir.join(dir_name);
            if !dir.exists() {
                continue;
            }
            self.walk_dir(&dir, &rules, &mut findings, &mut files_scanned);
        }

        // Check for .env files at root
        for env_name in &[".env", ".env.local", ".env.production"] {
            let env_path = self.base_dir.join(env_name);
            if env_path.exists() {
                files_scanned += 1;
                findings.push(AuditFinding {
                    id: format!("ENV-{}", env_name.replace('.', "")),
                    category: "secrets".to_string(),
                    severity: AuditSeverity::High,
                    title: format!("Ortam değişken dosyası bulundu: {}", env_name),
                    description: ".env dosyaları hassas bilgi içerebilir ve versiyon kontrolüne eklenmemelidir.".to_string(),
                    file_path: Some(env_name.to_string()),
                    line_number: None,
                    mitre_technique: Some("T1552.001".to_string()),
                    recommendation: ".env dosyasını .gitignore'a ekleyin ve gizli bilgileri güvenli bir vault'ta saklayın.".to_string(),
                    evidence: None,
                });
            }
        }

        findings.sort_by(|a, b| severity_rank(&b.severity).cmp(&severity_rank(&a.severity)));

        (findings, files_scanned)
    }

    fn walk_dir(
        &self,
        dir: &Path,
        rules: &[ScanRule],
        findings: &mut Vec<AuditFinding>,
        files_scanned: &mut usize,
    ) {
        let skip = ["target", "node_modules", ".git", "logs"];
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if skip.contains(&name) {
                        continue;
                    }
                    self.walk_dir(&path, rules, findings, files_scanned);
                } else if path.is_file() {
                    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                        let allowed = [
                            "rs", "js", "html", "toml", "json", "py", "ps1", "md", "yml", "yaml",
                            "css",
                        ];
                        if allowed.contains(&ext) {
                            self.scan_file(&path, rules, findings, files_scanned);
                        }
                    }
                }
            }
        }
    }

    fn scan_file(
        &self,
        path: &Path,
        rules: &[ScanRule],
        findings: &mut Vec<AuditFinding>,
        files_scanned: &mut usize,
    ) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(_) => return,
        };

        *files_scanned += 1;
        let rel_path = path
            .strip_prefix(&self.base_dir)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string();

        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        for rule in rules {
            if !rule.extensions.contains(&ext) {
                continue;
            }
            for (line_num, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*')
                {
                    // Skip obvious comments unless it's a hardcoded secret in comment
                }
                if rule.pattern.is_match(line) {
                    // Avoid duplicate findings for same file+rule
                    let finding_id = format!(
                        "{}-{}-{}",
                        rule.id,
                        rel_path.replace(['/', '\\'], "-"),
                        line_num + 1
                    );
                    if findings.iter().any(|f| f.id == finding_id) {
                        continue;
                    }
                    findings.push(AuditFinding {
                        id: finding_id,
                        category: rule.category.to_string(),
                        severity: rule.severity.clone(),
                        title: rule.title.to_string(),
                        description: rule.description.to_string(),
                        file_path: Some(rel_path.clone()),
                        line_number: Some((line_num + 1) as u32),
                        mitre_technique: rule.mitre.map(|m| m.to_string()),
                        recommendation: rule.recommendation.to_string(),
                        evidence: Some(truncate_evidence(line, 120)),
                    });
                }
            }
        }
    }

    fn build_rules(&self) -> Vec<ScanRule> {
        vec![
            ScanRule {
                id: "SEC-001",
                category: "secrets",
                severity: AuditSeverity::Critical,
                title: "Sabit kodlanmış parola/secret tespit edildi",
                description: "Kaynak kodda açık parola veya gizli anahtar bulundu.",
                pattern: Regex::new(r#"(?i)(password|passwd|secret|api_key|apikey|private_key)\s*[=:]\s*["'][^"']{4,}["']"#).unwrap(),
                mitre: Some("T1552.001"),
                recommendation: "Gizli bilgileri ortam değişkenlerine veya güvenli bir secret manager'a taşıyın.",
                extensions: &["rs", "js", "html", "toml", "py", "json"],
            },
            ScanRule {
                id: "SEC-002",
                category: "secrets",
                severity: AuditSeverity::Critical,
                title: "Hardcoded API anahtarı",
                description: "Sabit kodlanmış API anahtarı veya token bulundu.",
                pattern: Regex::new(r"(?i)(SOC-SIM-SECURE-KEY|token_secret_key|sim_secret)").unwrap(),
                mitre: Some("T1552.001"),
                recommendation: "API anahtarlarını runtime'da ortam değişkenlerinden yükleyin.",
                extensions: &["rs", "js", "toml"],
            },
            ScanRule {
                id: "SEC-003",
                category: "crypto",
                severity: AuditSeverity::High,
                title: "Zayıf hash algoritması (DefaultHasher)",
                description: "Parola hash'leme için kriptografik olmayan DefaultHasher kullanılıyor.",
                pattern: Regex::new(r"DefaultHasher").unwrap(),
                mitre: Some("T1552.001"),
                recommendation: "bcrypt, argon2 veya PBKDF2 gibi güvenli hash algoritmaları kullanın.",
                extensions: &["rs"],
            },
            ScanRule {
                id: "SEC-004",
                category: "auth",
                severity: AuditSeverity::High,
                title: "Varsayılan admin kimlik bilgileri",
                description: "Varsayılan admin/admin123 kimlik bilgileri kodda veya arayüzde bulundu.",
                pattern: Regex::new(r#"(?i)(admin123|value="admin"|Varsayılan Bilgiler)"#).unwrap(),
                mitre: Some("T1078.001"),
                recommendation: "Varsayılan kimlik bilgilerini kaldırın ve ilk kurulumda zorunlu parola değişikliği uygulayın.",
                extensions: &["rs", "js", "html"],
            },
            ScanRule {
                id: "SEC-005",
                category: "injection",
                severity: AuditSeverity::High,
                title: "SQL string birleştirme",
                description: "SQL sorgularında doğrudan string birleştirme tespit edildi — SQL injection riski.",
                pattern: Regex::new(r#"(?i)(format!\(.*SELECT|format!\(.*INSERT|format!\(.*UPDATE|format!\(.*DELETE)"#).unwrap(),
                mitre: Some("T1190"),
                recommendation: "Parametreli sorgular (prepared statements) kullanın.",
                extensions: &["rs"],
            },
            ScanRule {
                id: "SEC-006",
                category: "cors",
                severity: AuditSeverity::Medium,
                title: "CORS tüm origin'lere açık",
                description: "CORS yapılandırması tüm origin'lere izin veriyor (allow_origin Any).",
                pattern: Regex::new(r"allow_origin\(Any\)").unwrap(),
                mitre: Some("T1190"),
                recommendation: "CORS'u yalnızca güvenilen origin'lere kısıtlayın.",
                extensions: &["rs"],
            },
            ScanRule {
                id: "SEC-007",
                category: "xss",
                severity: AuditSeverity::Medium,
                title: "CSP unsafe-inline/unsafe-eval",
                description: "Content Security Policy unsafe-inline veya unsafe-eval içeriyor.",
                pattern: Regex::new(r"unsafe-inline|unsafe-eval").unwrap(),
                mitre: Some("T1059.007"),
                recommendation: "CSP'den unsafe-inline ve unsafe-eval direktiflerini kaldırın.",
                extensions: &["rs", "html"],
            },
            ScanRule {
                id: "SEC-008",
                category: "config",
                severity: AuditSeverity::Medium,
                title: "Debug/trace modu aktif olabilir",
                description: "Debug veya verbose logging yapılandırması tespit edildi.",
                pattern: Regex::new(r"(?i)(debug\s*=\s*true|RUST_LOG\s*=\s*debug|trace\(\))").unwrap(),
                mitre: None,
                recommendation: "Production ortamında debug modunu devre dışı bırakın.",
                extensions: &["rs", "toml", "yml"],
            },
            ScanRule {
                id: "SEC-009",
                category: "path_traversal",
                severity: AuditSeverity::High,
                title: "Path traversal riski",
                description: "Dosya yolu kullanıcı girdisinden doğrudan oluşturuluyor.",
                pattern: Regex::new(r"(?i)(\.\./|\.\.\\\\|PathBuf::from\(.*req\.|join\(.*req\.)").unwrap(),
                mitre: Some("T1083"),
                recommendation: "Dosya yollarını canonicalize edin ve base dizin dışına çıkışı engelleyin.",
                extensions: &["rs"],
            },
            ScanRule {
                id: "SEC-010",
                category: "encryption",
                severity: AuditSeverity::Medium,
                title: "Şifresiz veritabanı",
                description: "SQLite veritabanı şifreleme olmadan kullanılıyor.",
                pattern: Regex::new(r"simulator\.db|rusqlite").unwrap(),
                mitre: Some("T1552.001"),
                recommendation: "Hassas veriler için SQLCipher veya disk şifrelemesi kullanın.",
                extensions: &["rs", "toml"],
            },
            ScanRule {
                id: "SEC-011",
                category: "auth",
                severity: AuditSeverity::Medium,
                title: "Auth bypass — statik API anahtarı",
                description: "Middleware'de sabit bir API anahtarı ile auth bypass mümkün.",
                pattern: Regex::new(r#"token_str == "SOC-SIM-SECURE-KEY"#).unwrap(),
                mitre: Some("T1078"),
                recommendation: "Statik API anahtarı bypass'ını kaldırın; tüm istekler için geçerli token zorunlu kılın.",
                extensions: &["rs"],
            },
            ScanRule {
                id: "SEC-012",
                category: "input_validation",
                severity: AuditSeverity::Low,
                title: "Yetersiz input sanitization",
                description: "sanitize_input yalnızca uzunluk kısıtlaması yapıyor, HTML/script filtrelemiyor.",
                pattern: Regex::new(r"pub fn sanitize_input").unwrap(),
                mitre: Some("T1059.007"),
                recommendation: "HTML encoding ve whitelist tabanlı input doğrulama ekleyin.",
                extensions: &["rs"],
            },
        ]
    }
}

fn severity_rank(sev: &AuditSeverity) -> u8 {
    match sev {
        AuditSeverity::Critical => 5,
        AuditSeverity::High => 4,
        AuditSeverity::Medium => 3,
        AuditSeverity::Low => 2,
        AuditSeverity::Info => 1,
    }
}

fn truncate_evidence(line: &str, max: usize) -> String {
    let trimmed = line.trim();
    if trimmed.len() <= max {
        trimmed.to_string()
    } else {
        format!("{}...", &trimmed[..max])
    }
}
