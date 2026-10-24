"""Test-only PFX child that exceeds its CPU budget: the kernel delivers SIGXCPU."""

import resource

resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
while True:
    pass
