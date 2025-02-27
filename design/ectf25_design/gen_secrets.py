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
from loguru import logger
from ectf25_design.utils import *

def load_secret(secrets_bytes: bytes) -> dict:
    """ Load the secrets from the secrets binary
    
        :param secrets: Path to the secrets file
        :returns: Dictionary of the secrets
            {
                "subscription_key": subscription_key,
                "signature_public_key": ecc_public_key,
                "channel_keys": {channel_id_32_uint: channel_key_32_bytes, ...},
                "signature_private_key": ecc_private_key,
            }
    """
    # calculate the number of channel keys
    channel_key_num = (len(secrets_bytes) - 3 * 32) // 36
    subscription_key, ecc_public_key, *channel_keys_packet_tuple, ecc_private_key \
        = struct.unpack(f"<32s32s{channel_key_num * '36s'}32s", secrets_bytes)
    return {
        "subscription_key": subscription_key,
        "signature_public_key": ecc_public_key,
        "channel_keys": unpack_channel_keys_packet(channel_keys_packet_tuple),
        "signature_private_key": ecc_private_key,
    }

def channels_check(channels: list[int]) -> list[int]:
    """ Zhong: Check which channels are valid"""
    # if len(channels) > 9:
    #     exit("Too many channels")
    try:
        channels.insert(0, 0)
        channels_set = list(set(channels))
        # if len(channels_set) > 9:
        #     raise ValueError
        for channel in channels_set:
            struct.pack("I", channel)
    except Exception as e:
        logger.critical(f"Channel {channel} is invalid: {e}")
        raise ValueError(f"Channel {channel} is invalid: {e}")
    return channels_set

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
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            36 bytes: channel_id + channel_key
            32 bytes: ecc_private_key
        
    """
    
    """channel 0 is always assumed to be valid and will not be passed in the list
    https://rules.ectf.mitre.org/2025/specs/detailed_specs.html#:~:text=The%20function%20takes%20a%20list%20of%20channels%20that%20will%20be%20valid%20in%20the%20system%20and%20returns%20any%20secrets%20that%20will%20be%20passed%20to%20future%20steps.%20Channel%200%20is%20always%20assumed%20to%20be%20valid%20and%20will%20not%20be%20passed%20in%20the%20list.
    """
    channels = channels_check(channels)
    logger.debug(f"Generate secrets for channel {[channel_id for channel_id in channels]}")
    # Generate secret keys used to encrypt frames for each channel
    # Use AES-256-GCM in the provided WolfSSL
    channel_keys_packet_tuple = gen_channel_keys_packets(channels)
    #  Generate subscription key to encrypt the subscription.bin file
    subscription_key = gen_subscription_key()
    # Generate the public/private key-pair used to sign each
    ecc_public_key, ecc_private_key = gen_public_private_key_pair()

    # Pack secrets into secrets.bin following the format specification
    secrets_pack = struct.pack(f"<32s32s{len(channels) * '36s'}32s", \
        subscription_key, ecc_public_key, *channel_keys_packet_tuple, ecc_private_key)
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
    
# python design/ectf25_design/gen_secrets.py secrets/secrets.bin 1 2 3 4 --force
