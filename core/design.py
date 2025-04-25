"""
NOTICE OF LICENSE.

Copyright 2025 @AnabolicsAnonymous

Licensed under the Affero General Public License v3.0 (AGPL-3.0)

This program is free software: you can redistribute it and/or modify
it under the terms of the Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
"""

import sys
import os
from datetime import datetime
import re
try:
    from core.config import CONFIG
except ImportError:
    CONFIG = {}

# Load user config with defaults
tmp_user = CONFIG.get("user", {})
_DEFAULT_VERSION = tmp_user.get("BEACON_tag", "BEACON-v1.0.0")
_DEFAULT_IP = tmp_user.get("IP", "Automatic")
_match = re.search(r"v(\d+)", _DEFAULT_VERSION)
_MAJOR_VERSION = _match.group(1) if _match else _DEFAULT_VERSION
_EMBED_VERSION = _DEFAULT_VERSION.replace("-", " ")

# Load color config with defaults
_tmp_colors = CONFIG.get("colors", {})
_OK_BLUE_CODE = _tmp_colors.get("OK_BLUE", 34)
_OK_GREEN_CODE = _tmp_colors.get("OK_GREEN", 92)
_FAIL_CODE = _tmp_colors.get("FAIL", 91)
_PINK_CODE = _tmp_colors.get("PINK", 35)
_RESET_CODE = _tmp_colors.get("RESET", 0)

class BeaconVersion:
    """
    Class to display the BEACON version and IP address.
    """
    def __init__(self):
        self.version = _DEFAULT_VERSION
        self.major_version = _MAJOR_VERSION
        self.embed_version = _EMBED_VERSION
        self.default_ip = _DEFAULT_IP

class Color:
    """
    Class to display the colors for the BEACON version and IP address.
    """
    OK_BLUE = f"\033[{_OK_BLUE_CODE}m"
    OK_GREEN = f"\033[{_OK_GREEN_CODE}m"
    FAIL = f"\033[{_FAIL_CODE}m"
    PINK = f"\033[{_PINK_CODE}m"
    RESET = f"\033[{_RESET_CODE}m"

class Output:
    """
    Class to display the output for the BEACON version and IP address.
    """
    def __init__(self):
        self.beacon_version = BeaconVersion().version
        self.default_ip = BeaconVersion().default_ip
        self.filename = sys.argv[0]

    def get_output(self):
        """
        Get the output for the BEACON version and IP address.
        """
        return f"{Color.OK_BLUE}[{Color.FAIL}{self.beacon_version}{Color.OK_BLUE}]"\
            f"[{Color.PINK}{self.get_time()}{Color.OK_BLUE}]{Color.RESET}"

    @staticmethod
    def clear():
        """
        Clear the screen.
        """
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def get_time():
        """
        Get the time for the BEACON version and IP address.
        """
        return datetime.now().strftime("%d-%m-%y %H:%M:%S")

    @staticmethod
    def organize_ip(ip):
        """
        Organize the IP address for the BEACON version and IP address.
        """
        return f"{ip:^{15}}"
