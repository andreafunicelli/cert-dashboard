#!/usr/bin/env python3
"""Ansible vault password script: prints the password from the environment, fails closed.

Deliberately imports no application code; it reads only its own environment.
"""

import os
import sys

password = os.environ.get("CERT_DASHBOARD_VAULT_PASSWORD")
if not password:
    sys.exit(1)
sys.stdout.write(password + "\n")
