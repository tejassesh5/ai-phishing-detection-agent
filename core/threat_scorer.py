"""
Aggregates analyzer results into a single weighted threat score.
"""

import config


def compute_final_score(
    header_result:     dict,
    url_result:        dict,
    content_result:    dict,
    attachment_result: dict,
) -> dict:
    """
    Weighted average of sub-scores using SCORE_WEIGHTS from config.
    Returns overall score (0-100) + threat level + per-category breakdown.
    """
    weights = config.SCORE_WEIGHTS

    sub_scores = {
        "headers":     header_result.get("score", 0),
        "urls":        url_result.get("score", 0),
        "content":     content_result.get("score", 0),
        "attachments": attachment_result.get("score", 0),
    }

    total_weight = sum(weights.values())
    weighted_sum = sum(
        sub_scores[cat] * (weights[cat] / total_weight)
        for cat in sub_scores
    )
    final = round(weighted_sum)

    level = _threat_level(final)

    all_flags = (
        header_result.get("flags", []) +
        url_result.get("flags", []) +
        content_result.get("flags", []) +
        attachment_result.get("flags", [])
    )

    return {
        "final_score":  final,
        "threat_level": level,
        "sub_scores":   sub_scores,
        "all_flags":    all_flags,
        "flag_count":   len(all_flags),
    }


def _threat_level(score: int) -> str:
    for level, (low, high) in config.THREAT_LEVELS.items():
        if low <= score <= high:
            return level
    return "unknown"
