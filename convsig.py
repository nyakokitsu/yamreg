#!/usr/bin/env python3
import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

seed = base64.b64decode(os.environ["PRIVATE_SEED"])
key = Ed25519PrivateKey.from_private_bytes(seed)
pub = key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
print("ed25519:" + base64.b64encode(pub).decode())
