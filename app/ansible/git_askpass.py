#!/usr/bin/env python3
"""GIT_ASKPASS helper: answers git's username and password prompts from the environment.

Deliberately imports no application code; it reads only its own environment.
Any other prompt, or a missing token, exits non-zero without printing anything.
"""

import os
import sys

prompt = sys.argv[1] if len(sys.argv) > 1 else ""
token = os.environ.get("CERT_DASHBOARD_GIT_TOKEN")
if not token:
    sys.exit(1)
if prompt.startswith("Username"):
    sys.stdout.write("x-access-token\n")
elif prompt.startswith("Password"):
    sys.stdout.write(token + "\n")
else:
    sys.exit(1)
