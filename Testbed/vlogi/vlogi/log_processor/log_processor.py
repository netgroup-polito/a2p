import os
import re
import requests
import subprocess

from log_context import LogContext
from merge_requirements import merge_requirements
from utils import (
    FAS,
    FAS_MERGED,
    FAS_NEW,
    EXTRACTED_REQUIREMENTS,
    VNETWORK,
    DOCKER_COMPOSE_FILES,
    FWCONFIG_REQUEST_URLS,
    FWCONFIG_FILES,
)
from watchdog.events import FileSystemEvent, FileSystemEventHandler


class LogProcessor(FileSystemEventHandler):
    def __init__(self, ctx: LogContext):
        self.ctx = ctx
        self.last_position = 0

    def read_new_entries(self):
        with open(self.ctx.alert_file_path, "r") as file:
            file.seek(self.last_position)
            new_content = file.read()
            self.last_position = file.tell()

            return new_content

    def on_modified(self, event: FileSystemEvent):
        if event.src_path != self.ctx.alert_file_path:
            return

        new_entries = self.read_new_entries()

        if not new_entries:
            return

        # optional filtering here
        # LogFilter.script_filter(...)
        # LogFilter.api_filter(...)

        try:
            if not self._extract_requirements(new_entries):
                return

            merge_requirements()

            if not self.ctx.auto_confirm:
                while (
                    apply := input(
                        "Attack(s) detected. New requirements generated in 'FAS_merged.xml'. Apply changes to network? [Y/n] "
                    ).lower()
                    or "y"
                ) not in [
                    "y",
                    "n",
                ]:
                    pass
                apply = apply == "y"
            else:
                apply = self.ctx.auto_confirm

            if not apply:
                return

            # due to a bug requiring pre-generation of both FAS files, the new FAS is
            # temporarily written to FAS_new.xml
            #
            # future update: generate FAS files normally, directly write
            # to FAS.xml and adjust the subsequent methods accordingly
            # self._generate_new_fas()

            self._generate_vnetwork_files()

            self._generate_firewall_config_files()

            self._set_permissions()

            # self._replace_old_fas()

            self._start_vnetwork()

            print("\nDone!")
        except requests.RequestException as e:
            print(f"Error during API request: {e}")
        except IOError as e:
            print(f"File I/O error: {e}")

    def _extract_requirements(self, new_entries: str):
        url = f"http://localhost:8080/api/parser/{self.ctx.ids}/{self.ctx.version}/{self.ctx.alert_mode}"
        headers = {"Content-Type": "text/plain"}
        params = (
            {"priority": self.ctx.min_priority}
            if self.ctx.min_priority is not None
            else None
        )
        data = new_entries

        response = requests.post(url, headers=headers, params=params, data=data)
        response.raise_for_status()

        # check if response body is empty
        if response.text == "<PropertyDefinition/>":
            return False

        with open(EXTRACTED_REQUIREMENTS, "w") as file:
            file.write(response.text)

        return True

    def _generate_new_fas(self):
        with open(FAS_MERGED, "r") as f:
            data = f.read()

        url = "http://localhost:8085/verefoo/adp/simulations"
        headers = {"accept": "application/xml", "Content-Type": "application/xml"}

        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()

        with open(FAS_NEW, "w") as f:
            f.write(response.text)

    def _generate_vnetwork_files(self):
        with open(FAS_NEW, "r") as file:
            data = file.read()

        url = "http://localhost:8085/verefoo/adp/venvironment/generateFiles"
        params = {"firewallType": self.ctx.firewall_type}
        headers = {"Content-Type": "application/xml"}

        response = requests.post(url, headers=headers, params=params, data=data)
        response.raise_for_status()

    def _generate_firewall_config_files(self):
        # delete previous FAS
        response = requests.delete("http://localhost:8086/verefoo/fwd/nodes")
        response.raise_for_status()

        # add new FAS
        with open(FAS_NEW, "r") as file:
            data = file.read()

        url = "http://localhost:8086/verefoo/fwd/nodes/addnfv"
        headers = {"accept": "application/xml", "Content-Type": "application/xml"}

        response = requests.post(url, headers=headers, data=data)

        # generate firewall config files
        count = 0
        compiled_pattern = re.compile(r"container_name:\sfirewall")

        with open(DOCKER_COMPOSE_FILES[self.ctx.firewall_type], "r") as file:
            for line in file:
                count += len(compiled_pattern.findall(line))

        for i in range(1, count + 1):
            headers = {"accept": "*/*"}

            response = requests.get(
                FWCONFIG_REQUEST_URLS[self.ctx.firewall_type].format(i), headers=headers
            )
            response.raise_for_status()

            with open(FWCONFIG_FILES[self.ctx.firewall_type].format(i, i), "w") as file:
                file.write(response.text)

    def _set_permissions(self):
        subprocess.run(
            [
                "find",
                f"{VNETWORK}",
                "-type",
                "f",
                "-name",
                "*.sh",
                "-exec",
                "chmod",
                "+x",
                "{}",
                ";",
            ]
        )

    def _replace_old_fas(self):
        os.remove(FAS)
        os.rename(FAS_NEW, FAS)

    def _start_vnetwork(self):
        subprocess.run(
            [
                "bash",
                "-c",
                f"(cd {VNETWORK} && sudo ./startScript.sh {self.ctx.firewall_type.lower()})",
            ]
        )
