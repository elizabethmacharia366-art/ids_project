import os
import logging
import joblib
import numpy as np

log = logging.getLogger("ids.ml")

FEATURE_NAMES = [
    "packet_count", "byte_count", "bytes_per_sec", "packets_per_sec",
    "fwd_packets", "bwd_packets", "fwd_byte_ratio", "syn_count",
    "fin_count", "rst_count", "duration",
]


class AnomalyEngine:
    def __init__(self, model_path, scaler_path, score_threshold, min_packets):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.score_threshold = score_threshold
        self.min_packets = min_packets
        self.model = None
        self.scaler = None
        self._load()

    def _load(self):
        if os.path.exists(self.model_path) and os.path.exists(self.scaler_path):
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            log.info("Loaded ML model from %s", self.model_path)
        else:
            log.warning(
                "No trained model found at %s — ML scoring disabled until you run train_model.py",
                self.model_path,
            )

    def ready(self):
        return self.model is not None and self.scaler is not None

    def score_flow(self, flow):
        if not self.ready() or flow.packet_count < self.min_packets:
            return False, None
        vec = np.array(flow.to_feature_vector()).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)
        score = self.model.decision_function(vec_scaled)[0]
        is_anomalous = score < self.score_threshold
        return is_anomalous, float(score)
