# Software architecture documentation

## Introduction

### Purpose

The main goal of this document is to give a general overview of the architecture of vlogi.
It describes the roles and functions of each component, highlights how they work together, 
and provides guidance on how the software can be extended in the future.

### Scope

- __Functional boundaries__
  - vlogi is a command line utility designed for monitoring logs from Intrusion Detection Systems within a VEREFOO-generated virtual network
  - It detects new log entries and automatically integrates them into the network to mitigate active attacks

- __Supported formats__
  - vlogi is compatible with VIP's alert modes and formats
  - For instance, it can process both plaintext (`AlertFastV0` strategy) and JSON (`JsonOut` strategy) files

- __Extensibility__
  - vlogi is designed to be easily extensible
  - Through the `config.json` file, users can add new IDS/alert mode combinations for monitoring
  - The tool is prepared to work with external programs to filter the logs before they are integrated

- __Technological stack__
  - vlogi is written in Python 3.8.10
  - It uses the `requests` module to interact with VIP and VEREFOO, and employs the `watchdog` module for log file monitoring

## Architectural overview

![vlogi architecture](./img/vlogi_architecture.svg)

The diagram illustrates the main components of vlogi and how they interact.

- **Upon startup**:
  - vlogi pulls the required settings from the `config.json` file and the command line arguments, determines the alert file path for the session, and initializes a `LogContext` with this information
  - It then creates a `LogMonitor` instance with the new context and starts the monitoring process by calling the `start()` method


- **The `LogContext` contains**:
  - `ids`: name of the Intrusion Detection System being monitored
  - `version`: version of the IDS in use
  - `alert_mode`: format in which the IDS outputs its logs
  - `min_priority`: minimum priority level for alert processing
  - `alert_file_path`: full path to the alert log file
  - `auto_confirm`: whether to automatically confirm all actions without prompting or not
  - `firewall_type`: name of the firewall software for which policies will be generated


- **When a new alert is generated**:
  - The `LogProcessor`'s `on_modified()` method is triggered, capturing new log entries, possibly filtering them with the `LogFilter`, and updating the network's requirements accordingly
  - Depending on the `auto_confirm` setting, vlogi either directly applies the changes or prompts the user for confirmation. If confirmed, it generates new configuration files, applies the updates, and then returns to monitoring the logs


- **The `merge_requirements` module**:
  - Is used to merge the new Network Service Requirements extracted by the `LogProcessor` with the existing ones


- **The `utils` module**:
  - Includes the `get_alert_file_path()` function to determine the alert log file path during startup
  - Contains predefined constants and static paths to VEREFOO/vnetwork files necessary for other modules

## Configuration and usage

- **Before running**:
  - Ensure the `firewall-type` is correctly set in the `config.json` file
  - Make sure that your current working directory is set to the root project folder, not the inner `vlogi` folder
  - Launch VEREFOO and VIP, and then generate the initial set of required files
  - Create a subdirectory named `verefoo_network_files` and place your VEREFOO files there
  - Move your `vnetwork` folder inside the root project folder


- **To run the tool**:
  - Execute the command `python3 vlogi`, including the required arguments `ids`, `version`, and `alert_mode`
  - Depending on the IDS, you may need to specify the installation type (`server`, `agent`, `local`, or `hybrid`) using the `-i` option
  - Activate the `auto_confirm` feature using the `-a` flag if needed
  - Set the minimum priority level for alert processing using the `-p` option

## Extending vlogi

There are four distinct aspects in which vlogi can be extended:
1. **Adding new modules**:
   - To introduce a new module, create a directory with the desired module name inside the inner `vlogi` directory
   - Then, develop a Python script that will constitute your module's core logic
   - You can split the logic across multiple Python files, if needed
   - Finally, add an `__init__.py` file in your module's directory. This file will define which components of your module should be exposed to other parts of the application
2. **Adding new IDS/alert mode combinations**:
   - The `ids`, `version`, and `alert_mode` arguments in vlogi should correspond to those in the VIP tool
   - When a new IDS/alert mode is integrated into the VIP tool, update the `config.json` file to reflect these changes. This involves adding entries under the `logfiles` key
3. **Providing support for other firewall types**:
   - Support for additional firewall types is already in place
   - Once a new firewall type is supported by VEREFOO's virtual network translator, enable its integration in vlogi by uncommenting the relevant lines in `utils/firewall_types.py`
4. **Implementing the `LogFilter` class**:
   - The `LogFilter` class, as it currently stands, contains two placeholder static methods: `script_filter()` and `api_filter()`
   - The intention is to use these methods for preliminary filtering of logs before they undergo full processing