"""Test-only PFX child that answers with bytes that are not a valid response frame."""

import sys

sys.stdout.buffer.write(b"\xff\xff\xff\xffnot-a-frame")
