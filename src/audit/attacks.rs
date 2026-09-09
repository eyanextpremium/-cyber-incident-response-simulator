use std::path::Path;

use crate::scenarios::ScenarioLoader;
use crate::utils::{hash_password, parse_token, validate_session_id};

use super::report::AttackTestResult;

/// Simulated attack probes against the application's own security controls
pub struct AttackSimulator {
    base_dir: std::path::PathBuf,
    scenario_dir: std::path::PathBuf,
}

impl AttackSimulator {
    pub fn new(base_dir: &Path, scenario_dir: &Path) -> Self {
        Self {
            base_dir: base_dir.to_path_buf(),
            scenario_dir: scenario_dir.to_path_buf(),
        }
    }

    pub fn run_all(&self) -> Vec<AttackTestResult> {
        vec![
            self.test_default_credentials(),
            self.test_weak_password_hash(),
            self.test_token_bypass(),
            self.test_static_api_key(),
            self.test_sql_injection_scenario_id(),
            self.test_path_traversal_scenario(),
            self.test_xss_analyst_name(),
            self.test_session_id_validation(),
            self.test_empty_auth_token(),
            self.test_mitre_scenario_integrity(),
            self.test_scenario_file_permissions(),
            self.test_detection_rules_exist(),
        ]
    }

    fn test_default_credentials(&self) -> AttackTestResult {
        // Simulate checking if default admin123 password works
        let salt = "testsalt12345678";
        let hash = hash_password("admin123", salt);
        let is_weak_default = hash.len() < 64; // DefaultHasher produces short hashes

        AttackTestResult {
            test_id: "ATK-001".to_string(),
            name: "Varsayılan Kimlik Bilgileri Saldırısı".to_string(),
            description:
                "admin/admin123 varsayılan kimlik bilgileri ile giriş denemesi simülasyonu"
                    .to_string(),
            mitre_technique: "T1078.001".to_string(),
            passed: !is_weak_default,
            details: if is_weak_default {
                "Zayıf hash algoritması ve bilinen varsayılan parola (admin123) tespit edildi."
                    .to_string()
            } else {
                "Varsayılan kimlik bilgileri güvenli hash ile korunuyor.".to_string()
            },
        }
    }

    fn test_weak_password_hash(&self) -> AttackTestResult {
        let salt1 = "salt123456789012";
        let salt2 = "salt123456789012";
        let hash1 = hash_password("password1", salt1);
        let _hash2 = hash_password("password2", salt2);
        // DefaultHasher is deterministic for same input but different passwords should differ
        let uses_weak_hasher = hash1.len() == 32; // DefaultHasher hex output is 32 chars

        AttackTestResult {
            test_id: "ATK-002".to_string(),
            name: "Zayıf Parola Hash Saldırısı".to_string(),
            description: "Rainbow table / brute force saldırısına karşı hash gücü testi"
                .to_string(),
            mitre_technique: "T1110.002".to_string(),
            passed: !uses_weak_hasher,
            details: if uses_weak_hasher {
                "DefaultHasher kullanılıyor — kriptografik olmayan, hızlı hash. Brute force'a açık."
                    .to_string()
            } else {
                "Güçlü hash algoritması kullanılıyor.".to_string()
            },
        }
    }

    fn test_token_bypass(&self) -> AttackTestResult {
        let fake_tokens = [
            "",
            "invalid",
            "admin:admin:9999999999:deadbeef",
            "Bearer null",
        ];
        let mut bypass_found = false;
        for token in &fake_tokens {
            if parse_token(token).is_some() {
                bypass_found = true;
            }
        }

        AttackTestResult {
            test_id: "ATK-003".to_string(),
            name: "Token Bypass Saldırısı".to_string(),
            description: "Geçersiz/boş token ile auth bypass denemesi".to_string(),
            mitre_technique: "T1078".to_string(),
            passed: !bypass_found,
            details: if bypass_found {
                "Geçersiz token ile auth bypass mümkün!".to_string()
            } else {
                "Geçersiz token'lar reddediliyor.".to_string()
            },
        }
    }

    fn test_static_api_key(&self) -> AttackTestResult {
        // Check if hardcoded API key exists in middleware source
        let middleware_path = self.base_dir.join("src/api/middleware.rs");
        let has_static_key = std::fs::read_to_string(&middleware_path)
            .map(|c| c.contains("SOC-SIM-SECURE-KEY"))
            .unwrap_or(false);

        AttackTestResult {
            test_id: "ATK-004".to_string(),
            name: "Statik API Anahtarı Saldırısı".to_string(),
            description: "Hardcoded API anahtarı ile yetkisiz erişim denemesi".to_string(),
            mitre_technique: "T1552.001".to_string(),
            passed: !has_static_key,
            details: if has_static_key {
                "SOC-SIM-SECURE-KEY-2026 statik anahtarı middleware'de bulundu — auth bypass riski!"
                    .to_string()
            } else {
                "Statik API anahtarı tespit edilmedi.".to_string()
            },
        }
    }

    fn test_sql_injection_scenario_id(&self) -> AttackTestResult {
        let injection_payloads = [
            "' OR 1=1--",
            "1; DROP TABLE sessions;--",
            "admin' UNION SELECT * FROM users--",
        ];

        let loader = ScenarioLoader::new(&self.scenario_dir);
        let mut injection_possible = false;
        for payload in &injection_payloads {
            if loader.load_by_id(payload).is_ok() {
                injection_possible = true;
            }
        }

        AttackTestResult {
            test_id: "ATK-005".to_string(),
            name: "SQL Injection — Senaryo ID".to_string(),
            description: "Senaryo ID parametresine SQL injection payload enjeksiyonu".to_string(),
            mitre_technique: "T1190".to_string(),
            passed: !injection_possible,
            details: if injection_possible {
                "SQL injection payload'ı ile senaryo yüklenebildi!".to_string()
            } else {
                "SQL injection payload'ları senaryo yükleyicide etkisiz.".to_string()
            },
        }
    }

    fn test_path_traversal_scenario(&self) -> AttackTestResult {
        let traversal_ids = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "mitre/../../config/simulator.toml",
        ];

        let loader = ScenarioLoader::new(&self.scenario_dir);
        let mut traversal_possible = false;
        for id in &traversal_ids {
            if loader.load_by_id(id).is_ok() {
                traversal_possible = true;
            }
        }

        AttackTestResult {
            test_id: "ATK-006".to_string(),
            name: "Path Traversal — Dosya Erişimi".to_string(),
            description: "Path traversal ile sistem dosyalarına erişim denemesi".to_string(),
            mitre_technique: "T1083".to_string(),
            passed: !traversal_possible,
            details: if traversal_possible {
                "Path traversal ile yetkisiz dosya erişimi mümkün!".to_string()
            } else {
                "Path traversal saldırıları engellenmiş.".to_string()
            },
        }
    }

    fn test_xss_analyst_name(&self) -> AttackTestResult {
        let xss_payloads = [
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(document.cookie)",
        ];

        let mut xss_unfiltered = false;
        for payload in &xss_payloads {
            let sanitized = crate::utils::sanitize_input(payload, 100);
            if sanitized.contains('<') || sanitized.contains("javascript:") {
                xss_unfiltered = true;
            }
        }

        AttackTestResult {
            test_id: "ATK-007".to_string(),
            name: "XSS — Analist Adı Enjeksiyonu".to_string(),
            description: "Analist adı alanına XSS payload enjeksiyonu".to_string(),
            mitre_technique: "T1059.007".to_string(),
            passed: !xss_unfiltered,
            details: if xss_unfiltered {
                "XSS payload'ları sanitize edilmeden geçiyor!".to_string()
            } else {
                "XSS payload'ları ya filtreleniyor ya da uzunluk kısıtlaması ile sınırlandırılıyor (HTML encoding önerilir).".to_string()
            },
        }
    }

    fn test_session_id_validation(&self) -> AttackTestResult {
        let invalid_ids = ["", &"a".repeat(100), "../../../etc/passwd"];
        let mut invalid_accepted = false;
        for id in &invalid_ids {
            if validate_session_id(id) {
                invalid_accepted = true;
            }
        }

        AttackTestResult {
            test_id: "ATK-008".to_string(),
            name: "Oturum ID Doğrulama".to_string(),
            description: "Geçersiz oturum ID'leri ile erişim denemesi".to_string(),
            mitre_technique: "T1078".to_string(),
            passed: !invalid_accepted,
            details: if invalid_accepted {
                "Geçersiz oturum ID'leri kabul ediliyor!".to_string()
            } else {
                "Oturum ID doğrulaması çalışıyor.".to_string()
            },
        }
    }

    fn test_empty_auth_token(&self) -> AttackTestResult {
        let empty_accepted = parse_token("").is_some();

        AttackTestResult {
            test_id: "ATK-009".to_string(),
            name: "Boş Auth Token".to_string(),
            description: "Boş authorization token ile erişim denemesi".to_string(),
            mitre_technique: "T1078".to_string(),
            passed: !empty_accepted,
            details: if empty_accepted {
                "Boş token kabul ediliyor!".to_string()
            } else {
                "Boş token reddediliyor.".to_string()
            },
        }
    }

    fn test_mitre_scenario_integrity(&self) -> AttackTestResult {
        let loader = ScenarioLoader::new(&self.scenario_dir);
        let all = loader.load_all().unwrap_or_default();
        let mitre_count = all.iter().filter(|s| s.id.starts_with("mitre-")).count();
        let expected = 56;

        AttackTestResult {
            test_id: "ATK-010".to_string(),
            name: "MITRE Senaryo Bütünlüğü".to_string(),
            description: "56 MITRE ATT&CK senaryosunun varlık ve yüklenebilirlik kontrolü"
                .to_string(),
            mitre_technique: "TA0001".to_string(),
            passed: mitre_count >= expected,
            details: format!(
                "Beklenen: {} MITRE senaryo, Bulunan: {} (Toplam: {})",
                expected,
                mitre_count,
                all.len()
            ),
        }
    }

    fn test_scenario_file_permissions(&self) -> AttackTestResult {
        let mitre_dir = self.scenario_dir.join("mitre");
        let exists = mitre_dir.exists();
        let scenario_count = if exists {
            std::fs::read_dir(&mitre_dir)
                .map(|entries| entries.flatten().filter(|e| e.path().is_dir()).count())
                .unwrap_or(0)
        } else {
            0
        };

        AttackTestResult {
            test_id: "ATK-011".to_string(),
            name: "Senaryo Dosya Yapısı".to_string(),
            description: "MITRE senaryo dizin yapısı ve erişilebilirlik kontrolü".to_string(),
            mitre_technique: "T1083".to_string(),
            passed: exists && scenario_count >= 14,
            details: format!(
                "MITRE dizini: {}, Taktik klasör sayısı: {} (beklenen: 14)",
                if exists { "mevcut" } else { "eksik" },
                scenario_count
            ),
        }
    }

    fn test_detection_rules_exist(&self) -> AttackTestResult {
        let rules_path = self.base_dir.join("config/detection_rules.toml");
        let exists = rules_path.exists();
        let has_content = exists
            && std::fs::read_to_string(&rules_path)
                .map(|c| c.len() > 50)
                .unwrap_or(false);

        AttackTestResult {
            test_id: "ATK-012".to_string(),
            name: "Tespit Kuralları Varlığı".to_string(),
            description: "Detection rules yapılandırmasının varlık kontrolü".to_string(),
            mitre_technique: "T1562.001".to_string(),
            passed: has_content,
            details: if has_content {
                "Detection rules yapılandırması mevcut ve dolu.".to_string()
            } else {
                "Detection rules eksik veya boş — saldırılar tespit edilemeyebilir!".to_string()
            },
        }
    }
}
