"""Test-only PFX child that crashes and writes a secret-looking line to stderr."""

import sys

sys.stderr.write("secret-in-stderr\n")
sys.exit(3)
