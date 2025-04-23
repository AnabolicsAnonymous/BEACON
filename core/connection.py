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
import subprocess
import socket
import platform
import re
from typing import Tuple, Optional

class Connection:
    """
    Class to check the connection status/ping time and get the system's IP address.
    """
    def __init__(self):
        self.connection_statuses = ["Strong", "Great", "Weak"]
        self.ping_target = "8.8.8.8"
        self.ping_timeout = 1

    def _get_ping_command(self) -> str:
        """Get the appropriate ping command based on the operating system"""
        if platform.system().lower() == "windows":
            return f"ping -n 1 -w {self.ping_timeout * 1000}"
        return f"ping -c 1 -W {self.ping_timeout}"

    def get_connection_status(self) -> Tuple[str, Optional[float]]:
        """
        Get connection status and ping time.
        Returns a tuple of (status, ping_time) or ("ICMP Off", None) if ping fails.
        """
        try:
            command = f"{self._get_ping_command()} {self.ping_target}"
            output = subprocess.getoutput(command)

            ping_times = re.findall(r'time[=<](\d+(?:\.\d+)?)', output)
            if ping_times:
                ping_time = float(ping_times[0])

                if ping_time < 50:
                    status = self.connection_statuses[0]
                elif ping_time < 200:
                    status = self.connection_statuses[1]
                else:
                    status = self.connection_statuses[2]

                return status, round(ping_time, 2)

        except Exception:
            pass

        return "ICMP Off", None

    def get_system_ip(self, fallback_ip: str) -> str:
        """
        Get the system's IP address using multiple methods.
        Returns the first successful method or the fallback IP.
        """
        try:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(1)
                    s.connect((self.ping_target, 53))
                    return s.getsockname()[0]
            except Exception:
                pass

            try:
                hostname = socket.gethostname()
                return socket.gethostbyname(hostname)
            except Exception:
                pass

            if platform.system().lower() == "windows":
                try:
                    output = subprocess.getoutput("ipconfig")
                    ip_match = re.search(r'IPv4 Address.*?(\d+\.\d+\.\d+\.\d+)', output)
                    if ip_match:
                        return ip_match.group(1)
                except Exception:
                    pass
            else:
                try:
                    output = subprocess.getoutput("ip addr show")
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', output)
                    if ip_match:
                        return ip_match.group(1)
                except Exception:
                    pass

        except Exception:
            pass

        return fallback_ip
