# pylint: disable=no-name-in-module
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
import json
import time
import os
from decimal import Decimal
from collections import Counter
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def convert_decimal(obj):
    """
    Recursively convert elements to decimals to avoid serialization errors
    """
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, set):
        return list(obj)
    elif isinstance(obj, dict):
        return {key: convert_decimal(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_decimal(item) for item in obj]
    return obj

def update_ip_info(pcap_info, packet, ip_src_key, ip_src, counters):
    """
    Update the packet information in the pcap_info dictionary for a given IP source.
    """
    if ip_src not in pcap_info[ip_src_key]:
        pcap_info[ip_src_key][ip_src] = {
            "packets_from_ip": 0,
            "pps_from_ip": 0,
            "packet_types_from_ip": Counter(),
            "syn": 0,
            "ack": 0,
            "synack": 0,
            "fin": 0,
            "rst": 0,
            "psh": 0,
            "urg": 0,
            "ece": 0,
            "cwr": 0,
            "first_timestamp": round(packet.time, 2),
            "last_timestamp": packet.time,
            "source_ports": set(),
            "destination_ports": set(),
            "destination_ips": set()
        }

    ip_info = pcap_info[ip_src_key][ip_src]
    ip_info["packets_from_ip"] += 1
    ip_info["last_timestamp"] = round(packet.time, 2)

    packet_type = packet.__class__.__name__
    ip_info["packet_types_from_ip"][packet_type] += 1

    if TCP in packet or UDP in packet:
        protocol = TCP if TCP in packet else UDP
        process_transport_protocol(ip_info, packet, protocol, counters)

    process_ip_or_ipv6(ip_info, packet, counters)

    counters['source_ip'][ip_src] += 1

def process_transport_protocol(ip_info, packet, protocol, counters):
    """
    Process source and destination ports for TCP or UDP packets.
    """
    src_port = packet[protocol].sport
    dst_port = packet[protocol].dport
    ip_info["source_ports"].add(src_port)
    ip_info["destination_ports"].add(dst_port)

    counters['source_port'][src_port] += 1
    counters['dest_port'][dst_port] += 1

    if TCP in packet:
        flags = packet[TCP].flags
        flag_map = {
            "S": "syn", "A": "ack", "SA": "synack", "F": "fin", "R": "rst", 
            "P": "psh", "U": "urg", "E": "ece", "C": "cwr"
        }
        for flag, flag_name in flag_map.items():
            if flag in flags:
                ip_info[flag_name] += 1

def process_ip_or_ipv6(ip_info, packet, counters):
    """
    Process destination IP or IPv6 for the given packet.
    """
    dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst
    ip_info["destination_ips"].add(dst_ip)
    counters['dest_ip'][dst_ip] += 1

def extract_pcap_details(pcap):
    """
    Extract details from the given PCAP file, including information on IP addresses,
    ports, and packet statistics.
    """
    packets = rdpcap(pcap)

    pcap_info = {
        "pcap_name": pcap,
        "pcap_size_bytes": os.path.getsize(pcap),
        "pcap_packets_captured": len(packets),
        "pcap_date_captured": time.ctime(),
        "pcap_duration_seconds": round((packets[-1].time - packets[0].time), 2) if packets else 0,
        "most_common_source_ip": None,
        "most_common_dest_ip": None,
        "most_common_port_from": None,
        "most_common_port_to": None,
        "ipv4_addresses": {},
        "ipv6_addresses": {}
    }

    counters = {
        'source_ip': Counter(),
        'dest_ip': Counter(),
        'source_port': Counter(),
        'dest_port': Counter()
    }

    for packet in packets:
        if IP in packet:
            update_ip_info(pcap_info, packet, 'ipv4_addresses', packet[IP].src, counters)
        elif IPv6 in packet:
            update_ip_info(pcap_info, packet, 'ipv6_addresses', packet[IPv6].src, counters)

    pcap_info["most_common_source_ip"] = counters['source_ip']\
        .most_common(1)[0][0] if counters['source_ip'] else None
    pcap_info["most_common_dest_ip"] = counters['dest_ip']\
        .most_common(1)[0][0] if counters['dest_ip'] else None
    pcap_info["most_common_port_from"] = counters['source_port']\
        .most_common(1)[0][0] if counters['source_port'] else None
    pcap_info["most_common_port_to"] = counters['dest_port']\
        .most_common(1)[0][0] if counters['dest_port'] else None

    for ip_address in pcap_info['ipv4_addresses'].values():
        if ip_address["first_timestamp"] != ip_address["last_timestamp"]:
            ip_address["pps_from_ip"] = round(ip_address["packets_from_ip"] / \
            (ip_address["last_timestamp"] - ip_address["first_timestamp"]), 2)

    for ipv6_address in pcap_info['ipv6_addresses'].values():
        if ipv6_address["first_timestamp"] != ipv6_address["last_timestamp"]:
            ipv6_address["pps_from_ip"] = round(ipv6_address["packets_from_ip"] / \
            (ipv6_address["last_timestamp"] - ipv6_address["first_timestamp"]), 2)

    return pcap_info

def save_pcap_info_to_json(pcap_info, export_json):
    """
    Save the processed PCAP information to a JSON file.
    """
    pcap_info = convert_decimal(pcap_info)
    with open(export_json, 'w', encoding="utf-8") as json_file:
        json.dump(pcap_info, json_file, indent=4)

def main(pcap, export_json):
    """Module entry point, returns True if no errors occured"""
    try:
        pcap_file = extract_pcap_details(pcap)
        save_pcap_info_to_json(pcap_file, export_json)
        return True
    except Exception as e:
        return e
