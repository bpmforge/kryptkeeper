# Copyright 2026 Kryptkeeper Authors
# SPDX-License-Identifier: Apache-2.0
"""Expose this checkout as ansible_collections.kryptkeeper.pki without installing it."""
import os
import sys
import tempfile

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_base = tempfile.mkdtemp(prefix="kk-pki-collections-")
os.makedirs(os.path.join(_base, "ansible_collections", "kryptkeeper"))
os.symlink(_root, os.path.join(_base, "ansible_collections", "kryptkeeper", "pki"))
sys.path.insert(0, _base)
