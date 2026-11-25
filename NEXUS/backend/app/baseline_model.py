import math
from typing import Dict, Any, Tuple, Optional, List
from .config import (
    EWMA_ALPHA,
    Z_SCORE_THRESHOLD,
    STD_DEV_FLOOR,
    MIN_DEAUTH_COUNT,
    WARMUP_WINDOWS,
    FIXED_DEAUTH_THRESHOLD
)

class FeatureBaseline:
    """EWMA statistical baseline with 24-hour diurnal seasonal adjustment buckets."""

    def __init__(self, name: str, alpha: float = EWMA_ALPHA, std_dev_floor: float = STD_DEV_FLOOR):
        self.name = name
        self.alpha = alpha
        self.std_dev_floor = std_dev_floor
        self.mean: float = 0.0
        self.variance: float = 1.0
        self.initialized: bool = False

        # Diurnal hour-of-day seasonal buckets (h in 0..23)
        self.hourly_means: List[float] = [0.0] * 24
        self.hourly_counts: List[int] = [0] * 24

    def get_std_dev(self) -> float:
        # Prevent division by zero and enforce noise floor on discrete counts
        raw_sd = math.sqrt(max(self.variance, 0.0))
        return max(raw_sd, self.std_dev_floor)

    def get_effective_mean(self, hour: Optional[int] = None) -> float:
        """Returns the expected mean, incorporating diurnal seasonal bucket if present."""
        if hour is None:
            return self.mean
        h = int(hour) % 24
        if self.hourly_counts[h] == 0 or not self.initialized:
            return self.mean
        # Diurnal weighted blending: 0.65 global EWMA + 0.35 seasonal hourly bucket
        return (0.65 * self.mean) + (0.35 * self.hourly_means[h])

    def compute_z_score(self, observation: float, hour: Optional[int] = None) -> float:
        sd = self.get_std_dev()
        eff_mean = self.get_effective_mean(hour)
        return (observation - eff_mean) / sd

    def update(self, observation: float, hour: Optional[int] = None) -> None:
        obs = float(observation)
        if not self.initialized:
            self.mean = obs
            self.variance = 1.0
            self.initialized = True
        else:
            # EWMA recursive formulation: mu_t = alpha*mu_{t-1} + (1-alpha)*x_t
            diff = obs - self.mean
            self.mean = (self.alpha * self.mean) + ((1.0 - self.alpha) * obs)
            # Variance update: var_t = alpha*var_{t-1} + (1-alpha)*(x_t - mu_{t-1})^2
            self.variance = (self.alpha * self.variance) + ((1.0 - self.alpha) * (diff * diff))

        if hour is not None:
            h = int(hour) % 24
            if self.hourly_counts[h] == 0:
                self.hourly_means[h] = obs
            else:
                self.hourly_means[h] = (self.alpha * self.hourly_means[h]) + ((1.0 - self.alpha) * obs)
            self.hourly_counts[h] += 1

    def reset(self) -> None:
        self.mean = 0.0
        self.variance = 1.0
        self.initialized = False
        self.hourly_means = [0.0] * 24
        self.hourly_counts = [0] * 24


class AdaptiveBaselineEngine:
    """Coordinates multi-signal feature baselines with anomaly detection and seasonal adjustments."""

    def __init__(
        self,
        warmup_windows: int = WARMUP_WINDOWS,
        z_threshold: float = Z_SCORE_THRESHOLD,
        alpha: float = EWMA_ALPHA,
        fixed_threshold: int = FIXED_DEAUTH_THRESHOLD
    ):
        self.warmup_windows = warmup_windows
        self.warmup_limit = warmup_windows
        self.z_threshold = z_threshold
        self.alpha = alpha
        self.fixed_threshold = fixed_threshold
        self.processed_windows: int = 0
        self.manual_primary_ch: Optional[int] = None
        self.channel_activity: Dict[int, Dict[str, Any]] = {
            ch: {
                "mgmt_frames": 0,
                "bssid_count": 0,
                "windows": 0,
                "observed_bssids": set()
            }
            for ch in range(1, 14)
        }
        self.baselines: Dict[str, FeatureBaseline] = {
            "deauth": FeatureBaseline("deauth", alpha=self.alpha),
            "mgmt": FeatureBaseline("mgmt", alpha=self.alpha),
            "ble": FeatureBaseline("ble", alpha=self.alpha),
            "rogue": FeatureBaseline("rogue", alpha=self.alpha),
        }

    @property
    def is_warmed_up(self) -> bool:
        return self.processed_windows > self.warmup_windows

    def set_manual_primary_channel(self, channel: int) -> None:
        if 1 <= channel <= 13:
            self.manual_primary_ch = channel
        else:
            raise ValueError(f"Channel must be between 1 and 13, received {channel}")

    def get_optimal_scan_plan(self) -> Dict[str, Any]:
        """
        Calculates optimal adaptive scanning plan for the ESP32.
        Identifies the channel with highest sustained management frame density and legitimate BSSIDs.
        Duty cycle parameters: Primary dwell: 1700ms (85%), Patrol dwell: 50ms per off-channel (15% total across remaining 12 channels = 600ms patrol block).
        """
        if self.manual_primary_ch is not None and 1 <= self.manual_primary_ch <= 13:
            primary_ch = self.manual_primary_ch
        else:
            best_ch = 1
            highest_score = -1.0

            for ch in range(1, 14):
                hist = self.channel_activity[ch]
                win_cnt = hist.get("windows", 0)
                mgmt = float(hist.get("mgmt_frames", 0))
                bssids = float(hist.get("bssid_count", 0))

                density = (mgmt / float(win_cnt)) if win_cnt > 0 else 0.0
                score = density * (1.0 + bssids)

                if score > highest_score:
                    highest_score = score
                    best_ch = ch
                elif score == highest_score and highest_score > 0:
                    prev_best = self.channel_activity[best_ch]
                    if bssids > prev_best.get("bssid_count", 0):
                        best_ch = ch
                    elif bssids == prev_best.get("bssid_count", 0) and mgmt > prev_best.get("mgmt_frames", 0):
                        best_ch = ch

            primary_ch = best_ch

        return {
            "cmd": "scan_plan",
            "primary_ch": primary_ch,
            "dwell_primary_ms": 1700,
            "dwell_patrol_ms": 50
        }

    def evaluate_window(self, window_data: Dict[str, Any], hour: Optional[int] = None) -> Dict[str, Any]:
        self.processed_windows += 1
        flags: Dict[str, bool] = {}
        metrics: Dict[str, Dict[str, float]] = {}

        # Resolve hour for diurnal tracking if provided
        resolved_hour = hour
        if resolved_hour is None and "hour" in window_data:
            resolved_hour = int(window_data["hour"]) % 24

        # Track channel density and observed BSSID counts per channel across initial warmup windows
        if self.processed_windows <= self.warmup_windows:
            raw_ch = window_data.get("ch", window_data.get("channel", 1))
            try:
                ch = int(raw_ch) if raw_ch is not None else 1
            except (ValueError, TypeError):
                ch = 1

            if 1 <= ch <= 13:
                raw_mgmt = window_data.get("mgmt", window_data.get("mgmt_count", 0))
                try:
                    mgmt_cnt = int(raw_mgmt) if raw_mgmt is not None else 0
                except (ValueError, TypeError):
                    mgmt_cnt = 0

                raw_bssid = window_data.get("bssid_cnt", window_data.get("unique_bssids", 0))
                try:
                    bssid_cnt = int(raw_bssid) if raw_bssid is not None else 0
                except (ValueError, TypeError):
                    bssid_cnt = 0

                top_sources = window_data.get("top") or window_data.get("top_sources")

                ch_hist = self.channel_activity[ch]
                ch_hist["windows"] += 1
                ch_hist["mgmt_frames"] += max(mgmt_cnt, 0)

                if isinstance(top_sources, list):
                    for item in top_sources:
                        if isinstance(item, dict) and "bssid" in item:
                            ch_hist["observed_bssids"].add(str(item["bssid"]).upper())
                        elif isinstance(item, str):
                            ch_hist["observed_bssids"].add(item.upper())
                    ch_hist["bssid_count"] = max(ch_hist["bssid_count"], len(ch_hist["observed_bssids"]))

                if bssid_cnt > 0:
                    ch_hist["bssid_count"] = max(ch_hist["bssid_count"], bssid_cnt)

        for feat_name, baseline in self.baselines.items():
            obs_val = float(window_data.get(feat_name, 0))
            sd = baseline.get_std_dev()
            z = baseline.compute_z_score(obs_val, hour=resolved_hour)
            eff_mean = baseline.get_effective_mean(resolved_hour)

            metrics[feat_name] = {
                "observed": obs_val,
                "baseline_mean": round(eff_mean, 3),
                "baseline_sd": round(sd, 3),
                "z_score": round(z, 2)
            }

            flagged = False
            if self.is_warmed_up:
                if feat_name == "rogue":
                    flagged = (obs_val >= 1.0)
                elif feat_name == "deauth":
                    flagged = (z > self.z_threshold) and (obs_val >= MIN_DEAUTH_COUNT)
                else:
                    flagged = (z > self.z_threshold)

            flags[feat_name] = flagged

            # Suspend baseline updates during anomalous intervals to avoid poisoning
            if not flagged:
                baseline.update(obs_val, hour=resolved_hour)

        return {
            "window_id": self.processed_windows,
            "warmed_up": self.is_warmed_up,
            "flags": flags,
            "metrics": metrics
        }

    def adjust_sensitivity_on_false_positive(self, feature_name: str = "deauth") -> None:
        feat = feature_name.lower()
        if feat in self.baselines:
            b = self.baselines[feat]
            b.variance = max(b.variance * 1.5, 2.0)
            b.std_dev_floor = min(b.std_dev_floor + 0.3, 3.0)

    def get_hourly_profile(self, feature_name: str) -> List[float]:
        feat = feature_name.lower()
        if feat in self.baselines:
            return list(self.baselines[feat].hourly_means)
        return [0.0] * 24

    def update_parameters(
        self,
        alpha: Optional[float] = None,
        z_threshold: Optional[float] = None,
        warmup_windows: Optional[int] = None,
        fixed_threshold: Optional[int] = None
    ) -> Dict[str, Any]:
        """Dynamically tunes hyperparameters across active feature baselines."""
        if alpha is not None:
            self.alpha = float(alpha)
            for feat in self.baselines.values():
                feat.alpha = float(alpha)
        if z_threshold is not None:
            self.z_threshold = float(z_threshold)
        if warmup_windows is not None:
            self.warmup_windows = int(warmup_windows)
            self.warmup_limit = int(warmup_windows)
        if fixed_threshold is not None:
            self.fixed_threshold = int(fixed_threshold)
        return self.get_parameters()

    def get_parameters(self) -> Dict[str, Any]:
        """Returns active hyperparameters and configuration thresholds."""
        return {
            "alpha": getattr(self, "alpha", EWMA_ALPHA),
            "z_threshold": getattr(self, "z_threshold", Z_SCORE_THRESHOLD),
            "warmup_windows": getattr(self, "warmup_windows", WARMUP_WINDOWS),
            "warmup_limit": getattr(self, "warmup_limit", getattr(self, "warmup_windows", WARMUP_WINDOWS)),
            "fixed_threshold": getattr(self, "fixed_threshold", FIXED_DEAUTH_THRESHOLD)
        }

    def reset(self) -> None:
        self.processed_windows = 0
        self.manual_primary_ch = None
        self.alpha = EWMA_ALPHA
        self.z_threshold = Z_SCORE_THRESHOLD
        self.warmup_windows = WARMUP_WINDOWS
        self.warmup_limit = WARMUP_WINDOWS
        self.fixed_threshold = FIXED_DEAUTH_THRESHOLD
        self.channel_activity = {
            ch: {
                "mgmt_frames": 0,
                "bssid_count": 0,
                "windows": 0,
                "observed_bssids": set()
            }
            for ch in range(1, 14)
        }
        for b in self.baselines.values():
            b.alpha = EWMA_ALPHA
            b.reset()

# Alias for compatibility with project report and architecture specifications
BaselineModel = AdaptiveBaselineEngine
