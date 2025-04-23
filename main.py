# pylint: disable=broad-exception-caught
"""
NOTICE OF LICENSE.

Copyright 2025 @AnabolicsAnonymous

Licensed under the Affero General Public License v3.0 (AGPL-3.0)

This program is free software: you can redistribute it and/or modify
it under the terms of the Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""
import os
import sys
import re
import time
import json

try:
    import psutil
    from scapy.all import sniff, wrpcap, rdpcap, IP, TCP, UDP
    from core import config
    from core import connection
    from core import notifications as notis
    from core import design
    from core import export_packets

    FORMAT_OUTPUT = design.Output().get_output()
    color = design.Color()
    configure = config.CONFIG
except ImportError as e:
    from core import design
    FORMAT_OUTPUT = design.Output().get_output()
    if "core.configuration.config" in str(e):
        print(f"{FORMAT_OUTPUT} Error: config.py not found. Please check your installation.")
    else:
        print(f"{FORMAT_OUTPUT} Module imports failed: {e}")

    sys.exit()

class AttackVectors:
    """
    Class to load the attack vectors from the vectors.json file.
    """
    def __init__(self, filepath='vectors.json'):
        self.filepath = filepath
        self.attack_types = None
        self.attack_types_readable = None
        self.load_vectors()

    def load_vectors(self):
        """
        Load the attack vectors from the vectors.json file.
        """
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.attack_types = data["attack_types"]
                self.attack_types_readable = data["attack_types_readable"]
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            print(f"{FORMAT_OUTPUT} Error loading attack vectors: {str(e)}")
            sys.exit()

def create_directories():
    """
    Recursively create data directories, ignoring existing directory errors.
    """
    directories = [
        "./beacon_data/",
        "./beacon_data/pcaps/",
        "./beacon_data/detected_ips/",
        "./beacon_data/attack_data/",
    ]

    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except OSError as error:
            print(f"Error creating directory {directory}: {error}")

def trigger_check(pps, mbps):
    """
    Checks if traffic thresholds has been met and returning true/false
    """
    trigger_map = {
        "MP": int(pps) > int(configure["triggers"]["PPS_THRESH"]) \
            and int(mbps) > int(configure["triggers"]["MBPS_THRESH"]),
        "P": int(pps) > int(configure["triggers"]["PPS_THRESH"]),
        "M": int(mbps) > int(configure["triggers"]["MBPS_THRESH"]),
        "": False
    }

    try:
        return trigger_map[configure["triggers"]["Trigger"]]
    except KeyError:
        return False

def init():
    """
    Main entry point for the script
    """
    discord_notifier = notis.DiscordNotifier()
    attack_vectors = AttackVectors()
    system_ip = connection.Connection().get_system_ip(configure["user"]["IP"])

    while True:
        try:
            bytes_before = round(int(psutil.net_io_counters().bytes_recv) / 1024 / 1024 * 8, 3)
            packets_before = int(psutil.net_io_counters().packets_recv)

            time.sleep(1)

            bytes_after = round(int(psutil.net_io_counters().bytes_recv) / 1024 / 1024 * 8, 3)
            packets_after = int(psutil.net_io_counters().packets_recv)

            pps = packets_after - packets_before
            mbps = round(bytes_after - bytes_before)
            cpu = str(int(round(psutil.cpu_percent()))) + "%"
            conn_status, ping_time = connection.Connection().get_connection_status()

            print(f"{FORMAT_OUTPUT}{'IP Address:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{system_ip:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'CPU:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{cpu:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'Connection:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{conn_status:^{15}}{color.OK_BLUE}]{color.RESET}")
            if ping_time:
                print(f"{FORMAT_OUTPUT}{'Ping:':>23}{color.OK_BLUE} "\
                      +f"[{color.FAIL}{f'{ping_time}ms':^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'Megabits Per Second:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{mbps:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'Packets Per Second:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{pps:^{15}}{color.OK_BLUE}]{color.RESET}")

            if trigger_check(pps, mbps):
                print(f"{FORMAT_OUTPUT}{'Traffic Increased:':>23}{color.OK_BLUE} "\
                      +f"[{color.FAIL}{'Capturing...':^{15}}{color.OK_BLUE}]{color.RESET}")

                try:
                    timestamp = design.Output().get_time()
                    safe_timestamp = re.sub(r'[^\w.-]', '_', timestamp)

                    pcap_file = f"./beacon_data/pcaps/capture.{safe_timestamp}.pcap"

                    packets = sniff(count=configure["triggers"]["ConCount"], \
                                    iface=configure["capture"]["interface"])
                    wrpcap(pcap_file, packets)

                    attack_type_list = f"./beacon_data/attack_data/proto.{safe_timestamp}.txt"
                    packets = rdpcap(pcap_file)

                    with open(attack_type_list, "w", encoding="utf-8") as f:
                        f.write("ip.proto\ttcp.flags\tudp.srcport\ttcp.srcport\t")

                        for pkt in packets:
                            ip_proto = tcp_flags = udp_srcport = tcp_srcport = ""

                            if IP in pkt:
                                ip_proto = str(pkt[IP].proto)

                            if TCP in pkt:
                                tcp_flags = hex(int(pkt[TCP].flags))
                                tcp_srcport = str(pkt[TCP].sport)

                            if UDP in pkt:
                                udp_srcport = str(pkt[UDP].sport)

                            f.write(f"{ip_proto}\t{tcp_flags}\t{udp_srcport}\t{tcp_srcport}\n")

                    sys.stdout.write('\x1b[1A')
                    sys.stdout.write('\x1b[2K')
                    print(f"{FORMAT_OUTPUT}{'Traffic Increased:':>23}{color.OK_BLUE} "\
                          +f"[{color.FAIL}{'Captured!':^{15}}{color.OK_BLUE}]{color.RESET}")

                except ValueError as e:
                    print(f"{FORMAT_OUTPUT}{'Error:':>23} [{e}]")
                    sys.exit()

                file = open(attack_type_list, "r", encoding="utf-8")
                capture_file = file.read()
                file = file.close()

                attack_type = ''
                attack_type_readable = ''
                webhook_attack_vector = ''

                for occurrences in attack_vectors.attack_types:
                    number = capture_file.count(attack_vectors.attack_types[occurrences])
                    if number > int(configure["triggers"]["Attack_occurrences"]):
                        percentage = 100 * float(number)/float(configure["triggers"]["ConCount"])

                        attack_type = f"{attack_type}{occurrences} ({str(percentage)}%)]"

                for occurrences in attack_vectors.attack_types_readable:
                    number = capture_file.count(attack_vectors.attack_types_readable[occurrences])
                    if number > int(configure["triggers"]["Attack_occurrences"]):
                        percentage = 100 * float(number)/float(configure["triggers"]["ConCount"])

                        attack_type_readable = f"{attack_type_readable}{occurrences}" \
                            f"({str(percentage)}%)]"
                        webhook_attack_vector = f"{webhook_attack_vector}{occurrences}" \
                            f"({str(percentage)}%)]"

                if attack_type == '':
                    attack_type = f"{color.OK_BLUE} \
                        [{color.FAIL}{'Undetected':^{15}}{color.OK_BLUE}]{color.RESET}"

                if attack_type_readable == '':
                    attack_type_readable = "[Undetected]"

                print(f"{FORMAT_OUTPUT}{color.FAIL}{'Detected Method:':>{23}}" \
                      +f"{color.OK_BLUE} {attack_type}")

                try:
                    timestamp = design.Output().get_time()
                    safe_timestamp = re.sub(r'[^\w.-]', '_', timestamp)
                    export_json = f"./beacon_data/detected_ips/export.{safe_timestamp}.txt"
                    success = export_packets.main(pcap_file, export_json=export_json)
                    if success is not True:
                        print(success)
                    else:
                        display_export_data(export_json)
                except Exception as e:
                    print(e)
                    sys.exit()

                attack_data = {
                    "pps": pps,
                    "mbps": mbps,
                    "cpu": cpu,
                    "pcap": pcap_file,
                    "attack_vector": webhook_attack_vector or "Undetected"
                }
                discord_notifier.send_notification(attack_data, export_json)

                print(f"{FORMAT_OUTPUT}{color.FAIL}{'Pausing BEACON For:':>23} {color.OK_BLUE}" \
                    +f"[{color.FAIL}{str(configure['triggers']['PAUSE'])+' seconds':^{15}}" \
                    +f"{color.OK_BLUE}]{color.RESET}")

                time.sleep(int(configure["triggers"]["PAUSE"]))
                os.system('cls' if os.name == 'nt' else 'clear')

            for _ in range(6):
                sys.stdout.write('\x1b[1A')
                sys.stdout.write('\x1b[2K')
        except Exception as error:
            print(f"{FORMAT_OUTPUT}{'Error:':>23} [{error}]")
            sys.exit()

def display_export_data(export_json):
    """Display highlights from the export JSON file"""
    try:
        with open(export_json, 'r', encoding='utf-8') as f:
            export_data = json.load(f)

        if "ipv4_addresses" in export_data or "ipv6_addresses" in export_data:
            ipv4_count = len(export_data.get("ipv4_addresses", {}))
            ipv6_count = len(export_data.get("ipv6_addresses", {}))
            total_ips = ipv4_count + ipv6_count
            print(f"{FORMAT_OUTPUT}{'Total Unique IPs:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{total_ips:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'IPv4 Addresses:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{ipv4_count:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'IPv6 Addresses:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{ipv6_count:^{15}}{color.OK_BLUE}]{color.RESET}")

        if "most_common_source_ip" in export_data:
            print(f"{FORMAT_OUTPUT}{'Most Active Source:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{export_data['most_common_source_ip']:^{15}}"\
                  +f"{color.OK_BLUE}]{color.RESET}")

        if "most_common_dest_ip" in export_data:
            print(f"{FORMAT_OUTPUT}{'Most Active Dest.:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{export_data['most_common_dest_ip']:^{15}}"\
                  +f"{color.OK_BLUE}]{color.RESET}")

        if "pcap_packets_captured" in export_data and "pcap_duration_seconds" in export_data:
            packets = export_data["pcap_packets_captured"]
            duration = export_data["pcap_duration_seconds"]
            avg_pps = round(packets / duration) if duration > 0 else 0
            print(f"{FORMAT_OUTPUT}{'Total Packets:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{packets:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'Average PPS:':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{avg_pps:^{15}}{color.OK_BLUE}]{color.RESET}")
            print(f"{FORMAT_OUTPUT}{'Duration (s):':>23}{color.OK_BLUE} "\
                  +f"[{color.FAIL}{duration:^{15}}{color.OK_BLUE}]{color.RESET}")

    except Exception as e:
        print(f"{FORMAT_OUTPUT}{'Error reading export:':>23}{color.OK_BLUE} "\
              +f"[{color.FAIL}{str(e):^{15}}{color.OK_BLUE}]{color.RESET}")

if __name__ == '__main__':
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
        create_directories()
        init()
    except KeyboardInterrupt:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"\r{FORMAT_OUTPUT} Exception: KeyboardInterrupt")
        sys.exit()
