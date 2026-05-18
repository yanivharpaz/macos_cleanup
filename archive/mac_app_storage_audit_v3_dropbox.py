#!/usr/bin/env python3
"""Archived compatibility wrapper for the combined macOS app storage audit script."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mac_app_storage_audit_v2 import main


if __name__ == "__main__":
    raise SystemExit(main())
