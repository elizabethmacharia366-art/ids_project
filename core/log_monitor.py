import os
import time
import threading
import logging

log = logging.getLogger("ids.log_monitor")


class LogTailer:
    def __init__(self, paths, poll_interval_sec, on_line):
        self.paths = paths
        self.poll_interval_sec = poll_interval_sec
        self.on_line = on_line
        self._stop_event = threading.Event()
        self._thread = None
        self._offsets = {}

    def _open_existing_paths(self):
        existing = [p for p in self.paths if os.path.exists(p)]
        if not existing:
            log.warning("None of the configured host log paths exist: %s", self.paths)
        return existing

    def _tail_once(self, path):
        try:
            with open(path, "r", errors="ignore") as f:
                f.seek(self._offsets.get(path, os.path.getsize(path)))
                for line in f:
                    self.on_line(path, line.rstrip("\n"))
                self._offsets[path] = f.tell()
        except FileNotFoundError:
            pass
        except Exception:
            log.exception("Error tailing %s", path)

    def _run(self):
        paths = self._open_existing_paths()
        for p in paths:
            try:
                self._offsets[p] = os.path.getsize(p)
            except OSError:
                self._offsets[p] = 0
        log.info("Tailing host logs: %s", paths)
        while not self._stop_event.is_set():
            for p in paths:
                self._tail_once(p)
            time.sleep(self.poll_interval_sec)

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
