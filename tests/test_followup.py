"""Tests for orac.followup: recent-activity tracker + screener rate limit."""

from __future__ import annotations

import time

from orac import followup


def test_untouched_channel_is_not_recent() -> None:
    followup.reset()
    assert followup.was_recent("unused", window_s=60.0) is False
    assert followup.last_interaction_age("unused") is None


def test_touch_then_was_recent_within_window() -> None:
    followup.reset()
    followup.touch("Public")
    assert followup.was_recent("Public", window_s=60.0) is True
    age = followup.last_interaction_age("Public")
    assert age is not None and age < 1.0


def test_was_recent_expires_after_window() -> None:
    followup.reset()
    followup.touch("Public")
    # Immediately check with a zero-width window — should not count as recent.
    time.sleep(0.01)
    assert followup.was_recent("Public", window_s=0.001) is False


def test_screener_ok_rate_limits_per_channel() -> None:
    followup.reset()
    # First call allowed
    assert followup.screener_ok("Public", min_interval_s=0.5) is True
    # Immediate second call blocked
    assert followup.screener_ok("Public", min_interval_s=0.5) is False
    # Different channel not blocked
    assert followup.screener_ok("#general", min_interval_s=0.5) is True


def test_screener_ok_allows_after_interval() -> None:
    followup.reset()
    assert followup.screener_ok("Public", min_interval_s=0.05) is True
    time.sleep(0.1)
    assert followup.screener_ok("Public", min_interval_s=0.05) is True
