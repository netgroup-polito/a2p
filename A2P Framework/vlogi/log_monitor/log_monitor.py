import time

from log_context import LogContext
from log_processor import LogProcessor
from watchdog.observers import Observer


class LogMonitor:
    def __init__(self, ctx: LogContext):
        self.ctx = ctx
        self.observer = Observer()

    def start(self):
        event_handler = LogProcessor(self.ctx)
        self.observer.schedule(event_handler, self.ctx.alert_file_path, recursive=False)

        self.observer.start()
        try:
            while True:
                time.sleep(1)
        finally:
            self.stop()

    def stop(self):
        self.observer.stop()
        self.observer.join()
