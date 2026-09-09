/// Grade assigned to an analyst based on their total score
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Grade {
    S,
    A,
    B,
    C,
    D,
    F,
}

impl Grade {
    pub fn from_score(score: f64) -> Self {
        if score >= 95.0 {
            Self::S
        } else if score >= 80.0 {
            Self::A
        } else if score >= 65.0 {
            Self::B
        } else if score >= 50.0 {
            Self::C
        } else if score >= 35.0 {
            Self::D
        } else {
            Self::F
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::S => "S — Elite Analyst",
            Self::A => "A — Excellent",
            Self::B => "B — Good",
            Self::C => "C — Satisfactory",
            Self::D => "D — Needs Improvement",
            Self::F => "F — Critical Failure",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S => "S",
            Self::A => "A",
            Self::B => "B",
            Self::C => "C",
            Self::D => "D",
            Self::F => "F",
        }
    }
}

/// Full ranking info for a session result
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ranking {
    pub grade: Grade,
    pub score: f64,
    pub label: String,
    pub feedback: String,
}

impl Ranking {
    pub fn from_score(score: f64, time_secs: i64) -> Self {
        let grade = Grade::from_score(score);
        let feedback = generate_feedback(&grade, score, time_secs);
        let label = grade.label().to_string();
        Self {
            grade,
            score,
            label,
            feedback,
        }
    }
}

fn generate_feedback(grade: &Grade, score: f64, time_secs: i64) -> String {
    let time_str = format_time(time_secs);
    match grade {
        Grade::S => format!(
            "Outstanding performance! You completed the scenario in {} with a {:.1}/100 score. \
             All threats were detected, investigated, and remediated correctly.",
            time_str, score
        ),
        Grade::A => format!(
            "Excellent work! Score: {:.1}/100 in {}. Most threats were handled effectively \
             with minimal gaps in your response.",
            score, time_str
        ),
        Grade::B => format!(
            "Good response! Score: {:.1}/100 in {}. Some detection or containment steps \
             were delayed or missed. Review your investigation workflow.",
            score, time_str
        ),
        Grade::C => format!(
            "Satisfactory performance. Score: {:.1}/100 in {}. Several important response \
             actions were missed. Focus on systematic evidence collection and escalation.",
            score, time_str
        ),
        Grade::D => format!(
            "Below expectations. Score: {:.1}/100 in {}. Major response steps were skipped. \
             Review the incident response lifecycle and practice more beginner scenarios.",
            score, time_str
        ),
        Grade::F => format!(
            "Critical failure. Score: {:.1}/100 in {}. The attack was not adequately contained. \
             Restart with beginner scenarios and study the SOC methodology.",
            score, time_str
        ),
    }
}

fn format_time(secs: i64) -> String {
    let m = secs / 60;
    let s = secs % 60;
    if m > 0 {
        format!("{}m {}s", m, s)
    } else {
        format!("{}s", s)
    }
}
