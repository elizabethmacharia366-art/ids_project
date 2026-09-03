import argparse
import numpy as np
import pandas as pd

from detection.ml_engine import FEATURE_NAMES


def generate(n_rows, seed=42):
    rng = np.random.default_rng(seed)

    packet_count = rng.integers(2, 60, n_rows).astype(float)
    duration = rng.uniform(0.05, 20.0, n_rows)
    avg_pkt_size = rng.normal(500, 200, n_rows).clip(40, 1500)
    byte_count = packet_count * avg_pkt_size

    bytes_per_sec = byte_count / duration
    packets_per_sec = packet_count / duration

    fwd_ratio_pkts = rng.uniform(0.3, 0.7, n_rows)
    fwd_packets = (packet_count * fwd_ratio_pkts).round()
    bwd_packets = packet_count - fwd_packets
    fwd_byte_ratio = rng.uniform(0.3, 0.7, n_rows)

    syn_count = rng.integers(0, 2, n_rows).astype(float)
    fin_count = rng.integers(0, 2, n_rows).astype(float)
    rst_count = rng.integers(0, 1, n_rows).astype(float)

    df = pd.DataFrame({
        "packet_count": packet_count,
        "byte_count": byte_count,
        "bytes_per_sec": bytes_per_sec,
        "packets_per_sec": packets_per_sec,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "fwd_byte_ratio": fwd_byte_ratio,
        "syn_count": syn_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "duration": duration,
    })
    return df[FEATURE_NAMES]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="data/normal_flows.csv")
    parser.add_argument("--rows", type=int, default=5000)
    args = parser.parse_args()
    df = generate(args.rows)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} synthetic normal flows -> {args.out}")
