"""
baseline_engine.py - Re-exports AdaptiveBaselineEngine, FeatureBaseline, and BaselineModel.
Provides direct compatibility with architectural specs and remediation guidelines.
"""
from .baseline_model import (
    FeatureBaseline,
    AdaptiveBaselineEngine,
    BaselineModel
)

__all__ = [
    "FeatureBaseline",
    "AdaptiveBaselineEngine",
    "BaselineModel"
]
