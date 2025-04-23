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
import os
import re
import sys
from datetime import datetime, timezone
import requests
from core import config
from core import design

class DiscordNotifier:
    """
    Class to send notifications to Discord.
    """
    def __init__(self):
        """
        Initialize the DiscordNotifier class.
        """
        self.webhook_url = config.CONFIG["notification"]["Embed_Webhook_URL"]
        self.output = design.Output()
        self.export_dir = "./beacon_Data/detected_ips/"
        self.payload_template = self._load_payload_template()

    def _load_payload_template(self):
        """
        Load the Discord payload template from payload.json.
        
        Returns:
            dict: The loaded JSON template or exits if loading fails
        """
        template_path = 'payload.json'
        example_path = 'payload.json.example'

        if not os.path.exists(template_path):
            if os.path.exists(example_path):
                print(f"{self.output.get_output()} Error: payload.json not found.")
                print(f"{self.output.get_output()} Edit payload.json.example to payload.json")
            else:
                print(f"{self.output.get_output()} Error: Neither payload files found")
            sys.exit(1)

        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            print(f"{self.output.get_output()} Error: payload.json contains invalid JSON: {str(e)}")
            sys.exit(1)
        except Exception as e:
            print(f"{self.output.get_output()} Error loading payload template: {str(e)}")
            sys.exit(1)

    def mask_ip(self, ip):
        """
        Mask IPv4 and IPv6 addresses for privacy in webhooks.
        
        Args:
            ip (str): The IP address to mask
            
        Returns:
            str: The masked IP address (e.g., 192.xxx.xxx.xxx)
        """
        if ':' in ip:
            segments = ip.split(':')
            if len(segments) > 0:
                masked_segments = [segments[0]]
                for segment in segments[1:]:
                    if segment:
                        masked_segments.append('x' * len(segment))
                    else:
                        masked_segments.append('')
                return ':'.join(masked_segments)
        else:
            octets = ip.split('.')
            if len(octets) == 4:
                masked_octets = [octets[0]]
                for octet in octets[1:]:
                    masked_octets.append('x' * len(octet))
                return '.'.join(masked_octets)
        return ip

    def get_attack_count(self):
        """
        Count the number of files in the export directory.
        
        Returns:
            int: The number of attack files found
        """
        try:
            return len([f for f in os.listdir(self.export_dir) if f.endswith('.txt')])
        except Exception:
            return 0

    def read_export_json(self, json_file):
        """
        Read and parse an export JSON file.
        
        Args:
            json_file (str): Path to the JSON file to read
            
        Returns:
            dict: The parsed JSON data or None if reading fails
        """
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"{self.output.get_output()} Error reading export JSON: {str(e)}")
            return None

    def _clean_attack_vector(self, attack_vector):
        """
        Clean and format the attack vector string for display.
        
        Args:
            attack_vector (str): The raw attack vector string
            
        Returns:
            str: The cleaned and formatted attack vector
        """
        if not attack_vector:
            return "Undetected"
        cleaned = re.sub(r'\s+', ' ', attack_vector)
        cleaned = re.sub(r'\s*\]\s*', ']', cleaned)
        cleaned = re.sub(r'\s*\[\s*', '[', cleaned)
        return cleaned

    def send_notification(self, attack_data, export_json):
        """
        Send a notification to Discord using the configured webhook URL.
        
        Args:
            attack_data (dict): Dictionary containing attack info to be sent in the notification
            export_json (str): Path to the export JSON file containing additional attack data
            
        Returns:
            bool: True if notification was sent successfully, False otherwise
        """
        try:
            if not self.webhook_url:
                print(f"{self.output.get_output()} Error: Discord webhook URL not configured")
                return False

            if not self.payload_template:
                print(f"{self.output.get_output()} Error: Payload template not loaded")
                return False

            payload = json.loads(json.dumps(self.payload_template))
            attack_id = self.get_attack_count()
            export_data = {}
            embed = payload["embeds"][0]

            if export_json and os.path.exists(export_json):
                export_data = self.read_export_json(export_json) or {}

            embed["title"] = embed["title"].replace("{{attack_id}}", str(attack_id))
            embed["description"] = "BEACON has detected and analyzed a potential DDoS attack."
            embed["timestamp"] = datetime.now(timezone.utc).isoformat()

            for field in embed["fields"]:
                field["value"]=field["value"].replace("{{pps}}",str(attack_data.get("pps","N/A")))
                field["value"]=field["value"].replace("{{mbps}}",str(attack_data.get("mbps","N/A")))
                field["value"]=field["value"].replace("{{cpu}}",str(attack_data.get("cpu","N/A")))
                field["value"]=field["value"].replace("{{status}}","Detected")
                field["value"]=field["value"].replace("{{pcap}}",str(attack_data.get("pcap","N/A")))
                field["value"]=field["value"].replace("{{attack_vector}}",\
                    self._clean_attack_vector(attack_data.get("attack_vector","Undetected")))

                if export_data:
                    if "ipv4_addresses" in export_data or "ipv6_addresses" in export_data:
                        ipv4_count = len(export_data.get("ipv4_addresses", {}))
                        ipv6_count = len(export_data.get("ipv6_addresses", {}))
                        total_ips = ipv4_count + ipv6_count
                        field["value"] = field["value"].replace("{{total_ips}}", str(total_ips))
                        field["value"] = field["value"].replace("{{ipv4_count}}", str(ipv4_count))
                        field["value"] = field["value"].replace("{{ipv6_count}}", str(ipv6_count))

                    if "most_common_source_ip" in export_data:
                        masked_ip = self.mask_ip(export_data["most_common_source_ip"])
                        field["value"] = field["value"].replace("{{most_common_source_ip}}"\
                                                                , masked_ip)

                    if "most_common_dest_ip" in export_data:
                        masked_ip = self.mask_ip(export_data["most_common_dest_ip"])
                        field["value"] = field["value"].replace("{{most_common_dest_ip}}"\
                                                                , masked_ip)

                    if "pcap_packets_captured" in export_data \
                        and "pcap_duration_seconds" in export_data:
                        packets = export_data["pcap_packets_captured"]
                        duration = export_data["pcap_duration_seconds"]
                        avg_pps = round(packets / duration) if duration > 0 else 0
                        field["value"] = field["value"].replace("{{packets}}", str(packets))
                        field["value"] = field["value"].replace("{{avg_pps}}", str(avg_pps))

            embed["footer"]["text"] = embed["footer"]["text"]\
                .replace("{{pcap}}", str(attack_data.get("pcap", "N/A")))

            try:
                json.dumps(payload)
            except Exception as e:
                print(f"{self.output.get_output()} Error: Invalid payload format: {str(e)}")
                return False

            response = requests.post(
                self.webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if response.status_code != 204:
                print(f"{self.output.get_output()} Failed to send webhook: {response.status_code}")
                print(f"{self.output.get_output()} Response content: {response.text}")
                return False

            return True

        except Exception as e:
            print(f"{self.output.get_output()} Error sending Discord notification: {str(e)}")
            return False
