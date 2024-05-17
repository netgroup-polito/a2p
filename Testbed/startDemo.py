import re
import subprocess

from typing import List


class Colors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def print_wait(msg: str):
    print(f"{msg}", end="")
    input()


def print_run(cmd: List[str]):
    cmd_string = ' '.join(['"{}"'.format(arg.replace('"', '\\"')) if ' ' in arg or '"' in arg else arg for arg in cmd])
    print_wait(f"\n{Colors.OKBLUE}{cmd_string}{Colors.ENDC}\n")
    subprocess.run(cmd)


def print_cmd(cmd: str):
    print_wait(f"\n{Colors.OKCYAN}{cmd}{Colors.ENDC}\n")


def generate_fw_config_files():
    count = 0
    compiled_pattern = re.compile(r"container_name:\sfirewall")

    with open("vlogi/vnetwork/docker-compose-iptables.yml", "r") as file:
        for line in file:
            count += len(compiled_pattern.findall(line))

    for i in range(1, count + 1):
        print_run(["curl", "-X", "GET", f"http://localhost:8086/verefoo/fwd/deploy/getIptables/{i}", "-H", "accept: */*", "-o", f"vlogi/vnetwork/FirewallConfig/iptables/iptablesFirewall_{i}_{i}.sh"])


def main():
    # Introduction
    print_wait(f"{Colors.HEADER}Welcome to the full VEREFOO IDS demo!\n{Colors.ENDC}")
    print_wait("This demo includes two different networks, each with its own Intrusion Detection System.")
    print_wait(f"The first network uses {Colors.BOLD}Snort 3{Colors.ENDC}, a network-based IDS, while the second network uses {Colors.BOLD}OSSEC 3.7{Colors.ENDC}, a host-based IDS.")
    print_wait(f"Both demo versions will guide you through setting up an automated attack response system using the {Colors.BOLD}VEREFOO framework{Colors.ENDC}, along with the {Colors.BOLD}VIP{Colors.ENDC} and {Colors.BOLD}vlogi{Colors.ENDC} tools.")

    # Prerequisites
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n### PREREQUISITES ###\n{Colors.ENDC}")
    print_wait(f"Before we start, please download {Colors.BOLD}VIP{Colors.ENDC} and both the {Colors.BOLD}vforwarder-demo and react-verefoo-demo branches of VEREFOO{Colors.ENDC}.")
    print_wait("Once downloaded, you can generate the .jar files by executing the following command in each project directory:")
    print_cmd("mvn clean package")
    print_wait("The .jar files for this demo have already been generated, so we just need to run them:")
    # start all programs from the vlogi directory so verefoo's output is placed there
    print_run(["gnome-terminal", "--window", "--title=verefoo", "--command=bash -c '(cd vlogi && java -jar ../verefoo/verefoo.jar --server.port=8086)'", "--tab", "--title=react-verefoo", "--command=bash -c '(cd vlogi && java -jar ../verefoo/react-verefoo.jar)'", "--tab", "--title=vip", "--command=bash -c '(cd vlogi && java -jar ../vip/vip-0.0.1-SNAPSHOT.jar)'"])

    # Demo network selection
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n### DEMO NETWORK SELECTION ###\n{Colors.ENDC}")
    while True:
        print("1) Snort 3")
        print("2) OSSEC 3.7\n")
        
        choice = input("Which demo network would you like to select? ")
        
        if choice not in ["1", "2"]:
            print(f"{Colors.FAIL}Invalid choice. Please enter '1' or '2'.{Colors.ENDC}\n")
        else:
            break

    # Copy network files to vlogi folder
    chosen_ids = "snort3" if choice == "1" else "ossec37local"
    subprocess.run(["mkdir", "-p", "vlogi/verefoo_network_files"])
    subprocess.run(["cp", "-r", f"testfiles/{chosen_ids}/.", "vlogi/verefoo_network_files"])

    # Step 1
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n### STEP 1 ###\n{Colors.ENDC}")
    print_wait("Next, we'll generate the Firewall Allocation Scheme (FAS) for our virtual network using the following command (this step employs regular VEREFOO):")
    # right now, we're not actually running this command because VEREFOO has some issues with the XML output
    # we got the FAS file by running the Main class directly, but we're aiming to use API calls in the future
    print_cmd("curl -X POST http://localhost:8086/verefoo/adp/simulations -H \"accept: application/xml\" -H \"Content-Type: application/xml\" -d @vlogi/verefoo_network_files/Topology.xml > vlogi/verefoo_network_files/FAS.xml")
    print_wait(f"The command should have created a file named {Colors.BOLD}FAS.xml{Colors.ENDC} in the {Colors.BOLD}vlogi/verefoo_network_files{Colors.ENDC} directory.")

    # Step 2
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n### STEP 2 ###\n{Colors.ENDC}")
    print_wait("Now, we'll generate the necessary virtual network files (React-VEREFOO will be used moving forward):")
    print_run(["sudo", "rm", "-rf", "vlogi/vnetwork"])
    print_run(["curl", "-X", "POST", "http://localhost:8085/verefoo/adp/venvironment/generateFiles?firewallType=IPTABLES", "-H", "Content-Type: application/xml", "-d", "@vlogi/verefoo_network_files/FAS.xml"])
    print_wait(f"A new directory named {Colors.BOLD}vnetwork{Colors.ENDC} has been created inside the {Colors.BOLD}vlogi{Colors.ENDC} folder. This directory contains the files required to launch the virtual network.")
    print_wait("Let's review the generated virtual network:")
    print_run(["xdg-open", f"img/FAS_{chosen_ids}.png"])
    print_wait("It's time to generate the firewall configuration files.")
    print_wait("First, we'll store our FAS inside VEREFOO:")
    # this API call should also be handled by React-VEREFOO
    # since it hasn't been implemented into React-VEREFOO yet, we need to use regular VEREFOO
    print_run(["curl", "-X", "POST", "http://localhost:8086/verefoo/fwd/nodes/addnfv", "-H", "accept: application/xml", "-H", "Content-Type: application/xml", "-d", "@vlogi/verefoo_network_files/FAS.xml"])
    print_wait("Now, let's produce the configuration files for each firewall defined in our FAS:")
    generate_fw_config_files()
    print_wait("\nBefore booting up our virtual network, let's ensure that every script file has the execute permission:")
    # always use print_run(), I only did this to print the correct command
    print_wait(f"\n{Colors.OKBLUE}find vlogi/vnetwork -type f -name \"*.sh\" -exec chmod +x {{}} \\;{Colors.ENDC}\n")
    subprocess.run(["find", "vlogi/vnetwork", "-type", "f", "-name", "*.sh", "-exec", "chmod", "+x", "{}", ";"])
    print_wait("We're set to start our network:")
    print_run(["bash", "-c", "(cd vlogi/vnetwork && sudo ./startScript.sh iptables)"])
    print_wait("\nLastly, let's run vlogi:")
    print_run(["gnome-terminal", "--window", f"--title=vlogi-{chosen_ids}", "--command=bash -c '(cd vlogi && python3 vlogi snort 3 alertfastv0 -p 3)'" if choice == "1" else "--command=bash -c '(cd vlogi && python3 vlogi ossec 3.7 jsonout -i local)'"])

    # Step 3 
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n### STEP 3 ###\n{Colors.ENDC}")
    print_wait("We will now simulate an attack.")

    if choice == "1":
        print_wait(f"Let's start by opening a shell to {Colors.BOLD}server1{Colors.ENDC}, and {Colors.BOLD}client1{Colors.ENDC}:")
        print_run(["gnome-terminal", "--window", "--title=server1", "--command=sudo docker exec -it server1 /bin/sh", "--tab", "--title=client1", "--command=sudo docker exec -it client1 /bin/sh"])
        print_wait(f"{Colors.FAIL}\n<<< Please perform the following steps manually >>>\n{Colors.ENDC}")
        print_wait("On server1, set up a listener on port 7597:")
        print_cmd("nc -l -p 7597")
        print_wait("Simulate an attack from client1 to server1 with this command:")
        print_cmd("echo -n \"qazwsx.hsq\" | nc 130.10.0.4 7597")
    else:
        print_wait(f"Let's start by opening a shell to {Colors.BOLD}client1{Colors.ENDC}:")
        print_run(["gnome-terminal", "--window", "--title=client1", "--command=sudo docker exec -it client1 /bin/sh"])
        print_wait(f"{Colors.FAIL}\n<<< Please run the following command manually >>>\n{Colors.ENDC}")
        print_wait("Simulate a port scan from client1 to server1:")
        print_cmd("for port in $(seq 1 25); do nc 130.10.0.1 $port; done")

    print_wait("vlogi should detect the attack by reading the log files from the chosen IDS.")
    print_wait("After that, it will update the network's policies and ask you if you want to apply the changes.")
    print_wait("Accept the prompt and wait for vlogi to finish.")

    # Step 4
    print(f"{Colors.OKGREEN}{Colors.BOLD}\n### STEP 4 ###\n{Colors.ENDC}")
    print_wait("Let's have a look at the new virtual network:")
    print_run(["xdg-open", f"img/FAS_{chosen_ids}_new.png"])

    if choice == "1":
        print_wait(f"Notice that the rule on {Colors.BOLD}firewall1{Colors.ENDC}, which previously permitted TCP traffic on all destination ports, has been updated.")
        print_wait(f"It's now divided into two rules: one allowing traffic on destination ports {Colors.BOLD}0-7596 TCP{Colors.ENDC}, and the other on ports {Colors.BOLD}7598-65535 TCP{Colors.ENDC}.")
        print_wait(f"Given that the default action is {Colors.BOLD}DENY{Colors.ENDC}, traffic to port {Colors.BOLD}7597{Colors.ENDC} is now restricted.")
    else:
        print_wait(f"Notice that the rule on {Colors.BOLD}firewall1{Colors.ENDC}, which previously permitted TCP traffic on all destination ports, has been updated.")
        print_wait(f"It's now divided into three rules: the first one permits all traffic from servers to clients, the remaining two allow the {Colors.BOLD}192.168.3.0/24{Colors.ENDC} network to access {Colors.BOLD}server2{Colors.ENDC} and {Colors.BOLD}server3{Colors.ENDC} over TCP.")
        print_wait(f"Given that the default action is {Colors.BOLD}DENY{Colors.ENDC}, all TCP traffic from the {Colors.BOLD}192.168.3.0/24{Colors.ENDC} network towards {Colors.BOLD}server1{Colors.ENDC} is now restricted.")

    print_wait("\nIf everything went well, you should no longer be able to run the attack, and no alert will be triggered.")
    print_wait(f"Run the commands from {Colors.OKGREEN}Step 3{Colors.ENDC} again to confirm this:")

    if choice == "1":
        print_cmd("nc -l -p 7597")
        print_cmd("echo -n \"qazwsx.hsq\" | nc 130.10.0.4 7597")
    else:
        print_cmd("for port in $(seq 1 25); do nc 130.10.0.1 $port; done")

    # End
    print_wait(f"{Colors.HEADER}The demo has concluded. You are now free to explore and experiment on the virtual network on your own.{Colors.ENDC}")


if __name__ == "__main__":
    main()
