import threading
import time
import logging

from scapy.all import sniff, IP, TCP, UDP, ICMP

from core.flow import FlowTable

log = logging.getLogger("ids.capture")


class PacketCapture:
    def __init__(self, interface, bpf_filter, flow_table: FlowTable,
                 flush_interval_sec, flow_timeout_sec, on_flow_update=None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.flow_table = flow_table
        self.flush_interval_sec = flush_interval_sec
        self.flow_timeout_sec = flow_timeout_sec
        self.on_flow_update = on_flow_update
        self._stop_event = threading.Event()
        self._sniff_thread = None
        self._flush_thread = None

    def _handle_packet(self, pkt):
        if IP not in pkt:
            return
        ip_layer = pkt[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        length = len(pkt)
        proto, sport, dport, flags = "OTHER", 0, 0, ""

        if TCP in pkt:
            proto = "TCP"
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        elif ICMP in pkt:
            proto = "ICMP"

        flow, direction = self.flow_table.get_or_create(src_ip, dst_ip, sport, dport, proto)
        flow.update(length, flags, direction)

        if self.on_flow_update:
            try:
                self.on_flow_update(flow, src_ip, dst_ip, proto, flags)
            except Exception:
                log.exception("on_flow_update callback failed")

    def _sniff_loop(self):
        log.info("Starting capture on interface=%s filter='%s'", self.interface, self.bpf_filter)
        try:
            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            log.error("Permission denied opening interface %s. Run as root or grant CAP_NET_RAW.", self.interface)
        except Exception:
            log.exception("Capture loop terminated unexpectedly")

    def _flush_loop(self, on_expired_flow):
        while not self._stop_event.is_set():
            expired = self.flow_table.pop_expired(self.flow_timeout_sec)
            for flow in expired:
                try:
                    on_expired_flow(flow)
                except Exception:
                    log.exception("on_expired_flow callback failed")
            time.sleep(self.flush_interval_sec)

    def start(self, on_expired_flow):
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._flush_thread = threading.Thread(target=self._flush_loop, args=(on_expired_flow,), daemon=True)
        self._sniff_thread.start()
        self._flush_thread.start()

    def stop(self):
        self._stop_event.set()
