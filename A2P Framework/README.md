# VEREFOO Log Integrator (vlogi)

The **VEREFOO Log Integrator (vlogi)** is a command-line utility designed for monitoring logs from Intrusion Detection Systems within a VEREFOO-generated virtual network.
When vlogi detects new log entries in the files it monitors, it indicates a potential attack.
Upon detecting these new entries, vlogi extracts them and uses the VIP tool to convert them into VEREFOO requirements.
These new requirements are merged with the existing ones. Using VEREFOO, it generates updated FAS and network files.
With these new files, vlogi can then apply the changes to the running network to effectively counter the attack.

## Requirements

```
pip install -r requirements.txt
```

## Usage

Make sure to run VEREFOO and VIP from the root project folder. After running them, execute the vlogi tool from the same root project folder using the following command:
```
python3 vlogi [-h] [-i {server,agent,local,hybrid}] [-a] [-p MIN_PRIORITY] ids version alert_mode
```