#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    # Speed up the suite: the password hasher's cost is a production security
    # property, not something worth paying on every test run.
    if "test" in sys.argv:
        os.environ.setdefault("DALANID_FAST_HASHING", "1")
        # The suite asserts precise refusal codes and mints keys over HTTP.
        # Both are development affordances that ship disabled, so the tests
        # turn them on for themselves; the tests that prove the deployed
        # defaults behave correctly override them back off individually.
        os.environ.setdefault("DALANID_DEMO", "1")

    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dalanid.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
