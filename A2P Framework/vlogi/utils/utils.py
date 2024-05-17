from typing import Dict


INSTALLATION_TYPES = ["server", "agent", "local", "hybrid"]


def get_alert_file_path(
    log_folder_path: str,
    ids: str,
    version: str,
    alert_mode: str,
    installation_type: str,
    logfiles: Dict[str, Dict[str, str]],
):
    ids = ids.lower()
    version = version.replace(".", "")
    alert_mode = alert_mode.lower()

    alert_folder_path = f"{ids}{version}{installation_type}"
    alert_file_name = logfiles[alert_folder_path][alert_mode]

    return f"{log_folder_path}/{alert_folder_path}/{alert_file_name}"
