"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import json
from pathlib import Path
import struct
import secrets
from Crypto.PublicKey import ECC
from loguru import logger

#Liz - Adding a function to generate private 256-bit AES keys.
def gen_aes_key() -> bytes:
    key = secrets.token_bytes(32)
    return key

#Yi - generate subscription key 
def gen_subscription_key() -> bytes:
    return gen_aes_key()

def gen_channel_keys(channels: list[int]) -> tuple[bytes]:
    """Zhong - Generate the keys for each channel"""
    return (gen_aes_key() for _ in channels)

def gen_public_private_key_pair() -> tuple[bytes, bytes]:
    """ Generate the public/private key-pair 
        used to sign each frame so that the decoder can verify the frames originated from
        our encoder and subscription updates
        Reference: https://pycryptodome.readthedocs.io/en/latest/src/public_key/ecc.html#Crypto.PublicKey.ECC.EccKey
        
    :returns: Tuple of (public_key, private_key)
    """
    ecc_key = ECC.generate(curve="Ed25519")
    ecc_private_key = ecc_key.seed
    ecc_public_key = ecc_key.public_key().export_key(format="raw")
    return ecc_public_key, ecc_private_key


def load_secret(secrets_bytes: bytes) -> dict:
    """ Load the secrets from the secrets binary
    
        :param secrets: Path to the secrets file
        :returns: Dictionary of the secrets
            {
                "subscription_key": subscription_key,
                "signature_public_key": ecc_public_key,
                "channel_keys": [CH1_KEY, CH2_KEY, ...],
                "signature_private_key": ecc_private_key,
            }
    """
    # calculate the number of channel keys
    channel_key_num = len(secrets_bytes) // 32 - 3
    subscription_key, ecc_public_key, *channel_keys_tuple, ecc_private_key \
        = struct.unpack(f"<32s32s{channel_key_num * '32s'}32s", secrets_bytes)
    return {
        "subscription_key": subscription_key,
        "signature_public_key": ecc_public_key,
        "channel_keys": channel_keys_tuple,
        "signature_private_key": ecc_private_key,
    }


def gen_secrets(channels: list[int]) -> bytes:
    """Generate the contents secrets file

    This will be passed to the Encoder, ectf25_design.gen_subscription, and the build
    process of the decoder

    :param channels: List of channel numbers that will be valid in this deployment.
        Channel 0 is the emergency broadcast, which will always be valid and will
        NOT be included in this list

    :returns: Contents of the secrets file
        :rtype: bytes
        :format specification for secrets.bin:
            32 bytes: subscription_key
            32 bytes: ecc_public_key
            32 bytes: channel_key_0
            32 bytes: channel_key_1
            32 bytes: channel_key_2
            32 bytes: channel_key_3
            32 bytes: channel_key_4
            32 bytes: ecc_private_key
        
    """
    # Generate secret keys used to encrypt frames for each channel
    # Use AES-256-GCM in the provided WolfSSL
    channel_keys_tuple = gen_channel_keys(channels)
    #  Generate subscription key to encrypt the subscription.bin file
    subscription_key = gen_subscription_key()
    # Generate the public/private key-pair used to sign each
    ecc_public_key, ecc_private_key = gen_public_private_key_pair()

    # Pack secrets into secrets.bin following the format specification
    secrets_pack = struct.pack(f"<32s32s{len(channels) * '32s'}32s", \
        subscription_key, ecc_public_key, *channel_keys_tuple, ecc_private_key)
    
    return secrets_pack

def parse_args():
    """Define and parse the command line arguments

    NOTE: Your design must not change this function
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of secrets file, overwriting existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of gen_secrets

    You will likely not have to change this function
    """
    # Parse the command line arguments
    args = parse_args()

    secrets = gen_secrets(args.channels)

    # Print the generated secrets for your own debugging
    # Attackers will NOT have access to the output of this, but feel free to remove
    #
    # NOTE: Printing sensitive data is generally not good security practice
    logger.debug(f"Generated secrets: {secrets}; length: {len(secrets)}")

    # Open the file, erroring if the file exists unless the --force arg is provided
    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        # Dump the secrets to the file
        f.write(secrets)

    # For your own debugging. Feel free to remove
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
