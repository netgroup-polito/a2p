import argparse
import json

from log_context import LogContext
from log_monitor import LogMonitor
from utils import INSTALLATION_TYPES, get_alert_file_path, FirewallTypes, LOG_FOLDER


def parse_args():
    parser = argparse.ArgumentParser(description="VEREFOO Log Integrator")
    parser.add_argument("ids", help="name of the IDS for log file monitoring")
    parser.add_argument("version", help="version of the specified IDS")
    parser.add_argument(
        "alert_mode", help="alert mode that the specified IDS uses to generate logs"
    )
    parser.add_argument(
        "-i",
        "--installation-type",
        choices=INSTALLATION_TYPES,
        default="",
        help="installation type of the specified IDS",
    )
    parser.add_argument(
        "-a",
        "--auto-confirm",
        action="store_true",
        help="automatically confirm all actions without prompting",
    )
    parser.add_argument(
        "-p",
        "--min-priority",
        type=int,
        default=None,
        help="minimum priority level for alert processing",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    with open("config.json") as config_file:
        config = json.load(config_file)

    try:
        alert_file_path = get_alert_file_path(
            LOG_FOLDER,
            args.ids,
            args.version,
            args.alert_mode,
            args.installation_type,
            config.get("logfiles"),
        )
    except KeyError:
        print(f"Error: invalid parameters given")
        return

    firewall_type = config.get("firewall-type")
    try:
        FirewallTypes(firewall_type)
    except ValueError:
        print(f"Error: unsupported firewall type")
        return

    ctx = LogContext(
        ids=args.ids,
        version=args.version,
        alert_mode=args.alert_mode,
        min_priority=args.min_priority,
        alert_file_path=alert_file_path,
        auto_confirm=args.auto_confirm,
        firewall_type=firewall_type,
    )

    monitor = LogMonitor(ctx)
    monitor.start()


if __name__ == "__main__":
    main()
