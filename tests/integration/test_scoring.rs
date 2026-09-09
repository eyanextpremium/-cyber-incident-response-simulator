// Unit tests for scoring system components

use cyber_incident_simulator::scoring::{Grade, Ranking, ScoreMetrics, ScoringConfig};

#[test]
fn test_scoring_config_creation() {
    let config = ScoringConfig {
        max_score: 100.0,
        detection_points: 25.0,
        investigation_points: 25.0,
        containment_points: 25.0,
        recovery_points: 25.0,
        false_positive_penalty: 5.0,
        missed_alert_penalty: 10.0,
        time_penalty_factor: 0.005,
    };

    assert_eq!(config.detection_points, 25.0);
    assert_eq!(config.investigation_points, 25.0);
    assert_eq!(config.containment_points, 25.0);
    assert_eq!(config.recovery_points, 25.0);
    assert_eq!(config.time_penalty_factor, 0.005);
}

#[test]
fn test_weight_normalization() {
    // Test that category points sum to max_score
    let config = ScoringConfig::default();

    let total_points = config.detection_points
        + config.investigation_points
        + config.containment_points
        + config.recovery_points;

    assert!((total_points - config.max_score).abs() < 0.0001);
}

#[test]
fn test_score_metrics_creation() {
    let metrics = ScoreMetrics {
        detection_score: 25.0,
        investigation_score: 20.0,
        containment_score: 25.0,
        recovery_score: 15.0,
        time_penalty: 2.5,
        false_positive_penalty: 0.0,
        total_score: 82.5,
        time_elapsed_secs: 450,
    };

    assert_eq!(metrics.detection_score, 25.0);
    assert_eq!(metrics.investigation_score, 20.0);
    assert_eq!(metrics.containment_score, 25.0);
    assert_eq!(metrics.recovery_score, 15.0);
    assert_eq!(metrics.total_score, 82.5);
    assert_eq!(metrics.time_elapsed_secs, 450);
}

#[test]
fn test_total_score_calculation() {
    let mut metrics = ScoreMetrics {
        detection_score: 25.0,
        investigation_score: 20.0,
        containment_score: 25.0,
        recovery_score: 20.0,
        time_penalty: 5.0,
        false_positive_penalty: 5.0,
        total_score: 0.0,
        time_elapsed_secs: 450,
    };

    metrics.calculate_total();
    assert_eq!(metrics.total_score, 80.0);
}

#[test]
fn test_time_penalty_calculation() {
    let config = ScoringConfig::default();
    let time_elapsed_secs = 600;
    let expected_penalty = time_elapsed_secs as f64 * config.time_penalty_factor;

    assert!((expected_penalty - 3.0).abs() < 0.01);
}

#[test]
fn test_score_bounds() {
    let valid_scores = vec![0.0, 50.0, 75.5, 100.0];

    for score in valid_scores {
        assert!(score >= 0.0);
        assert!(score <= 100.0);
    }
}

#[test]
fn test_score_clamping() {
    let mut metrics = ScoreMetrics {
        detection_score: 80.0,
        investigation_score: 80.0,
        containment_score: 80.0,
        recovery_score: 80.0,
        time_penalty: 0.0,
        false_positive_penalty: 0.0,
        total_score: 0.0,
        time_elapsed_secs: 300,
    };

    metrics.calculate_total();
    assert_eq!(metrics.total_score, 100.0); // Clamped to 100

    let mut negative_metrics = ScoreMetrics {
        detection_score: 0.0,
        investigation_score: 0.0,
        containment_score: 0.0,
        recovery_score: 0.0,
        time_penalty: 50.0,
        false_positive_penalty: 50.0,
        total_score: 0.0,
        time_elapsed_secs: 300,
    };

    negative_metrics.calculate_total();
    assert_eq!(negative_metrics.total_score, 0.0); // Clamped to 0
}

#[test]
fn test_scoring_with_zero_recovery() {
    let mut metrics = ScoreMetrics {
        detection_score: 25.0,
        investigation_score: 25.0,
        containment_score: 25.0,
        recovery_score: 0.0,
        time_penalty: 0.0,
        false_positive_penalty: 0.0,
        total_score: 0.0,
        time_elapsed_secs: 300,
    };

    metrics.calculate_total();
    assert_eq!(metrics.recovery_score, 0.0);
    assert_eq!(metrics.total_score, 75.0);
}

#[test]
fn test_perfect_score() {
    let config = ScoringConfig::default();
    let mut metrics = ScoreMetrics {
        detection_score: config.detection_points,
        investigation_score: config.investigation_points,
        containment_score: config.containment_points,
        recovery_score: config.recovery_points,
        time_penalty: 0.0,
        false_positive_penalty: 0.0,
        total_score: 0.0,
        time_elapsed_secs: 0,
    };

    metrics.calculate_total();
    assert_eq!(metrics.total_score, 100.0);
}

#[test]
fn test_ranking_and_grades() {
    let grade_s = Grade::from_score(98.0);
    assert_eq!(grade_s, Grade::S);

    let grade_a = Grade::from_score(85.0);
    assert_eq!(grade_a, Grade::A);

    let grade_b = Grade::from_score(70.0);
    assert_eq!(grade_b, Grade::B);

    let grade_f = Grade::from_score(20.0);
    assert_eq!(grade_f, Grade::F);

    let ranking = Ranking::from_score(92.0, 120);
    assert_eq!(ranking.grade, Grade::A);
    assert_eq!(ranking.score, 92.0);
}

#[test]
fn test_scoring_config_validation() {
    let config = ScoringConfig::default();

    assert!(config.detection_points > 0.0);
    assert!(config.investigation_points > 0.0);
    assert!(config.containment_points > 0.0);
    assert!(config.recovery_points > 0.0);
    assert!(config.time_penalty_factor > 0.0);
}
