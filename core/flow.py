import time
import threading


class Flow:

    __slots__ = (
        "src_ip", "dst_ip", "src_port", "dst_port", "proto",
        "start_time", "last_seen", "packet_count", "byte_count",
        "syn_count", "fin_count", "rst_count",
        "fwd_packets", "bwd_packets", "fwd_bytes", "bwd_bytes",
    )

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        now = time.time()
        self.start_time = now
        self.last_seen = now
        self.packet_count = 0
        self.byte_count = 0
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.fwd_packets = 0
        self.bwd_packets = 0
        self.fwd_bytes = 0
        self.bwd_bytes = 0

    def update(self, length, flags, direction):
        self.last_seen = time.time()
        self.packet_count += 1
        self.byte_count += length
        if direction == "fwd":
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.bwd_packets += 1
            self.bwd_bytes += length
        if flags:
            if "S" in flags and "A" not in flags:
                self.syn_count += 1
            if "F" in flags:
                self.fin_count += 1
            if "R" in flags:
                self.rst_count += 1

    def duration(self):
        return max(self.last_seen - self.start_time, 1e-6)

    def to_feature_vector(self):
        dur = self.duration()
        return [
            self.packet_count,
            self.byte_count,
            self.byte_count / dur,
            self.packet_count / dur,
            self.fwd_packets,
            self.bwd_packets,
            (self.fwd_bytes / self.byte_count) if self.byte_count else 0.0,
            self.syn_count,
            self.fin_count,
            self.rst_count,
            dur,
        ]

    def key(self):
        return (self.src_ip, self.dst_ip, self.src_port, self.dst_port, self.proto)


class FlowTable:

    def __init__(self):
        self._flows = {}
        self._lock = threading.Lock()

    def get_or_create(self, src_ip, dst_ip, src_port, dst_port, proto):
        key = (src_ip, dst_ip, src_port, dst_port, proto)
        rev_key = (dst_ip, src_ip, dst_port, src_port, proto)
        with self._lock:
            if key in self._flows:
                return self._flows[key], "fwd"
            if rev_key in self._flows:
                return self._flows[rev_key], "bwd"
            flow = Flow(src_ip, dst_ip, src_port, dst_port, proto)
            self._flows[key] = flow
            return flow, "fwd"

    def pop_expired(self, timeout_sec):
        now = time.time()
        expired = []
        with self._lock:
            for key in list(self._flows.keys()):
                flow = self._flows[key]
                if now - flow.last_seen > timeout_sec:
                    expired.append(flow)
                    del self._flows[key]
        return expired

    def snapshot(self):
        with self._lock:
            return list(self._flows.values())
