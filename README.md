# JHU-MITRE eCTF Satellite TV System

This repository contains the design, firmware, and tools for Johns Hopkins University's entry in the MITRE 2025 Embedded Capture The Flag (eCTF) competition. The project demonstrates secure satellite TV decoder infrastructure along with host-side tools for managing subscriptions, updates, and system verification.

## Repository Structure

- **decoder/**: Firmware source for the satellite television decoder device.
- **design/**: Host-side design elements and subscription management utilities.
- **tools/**: Host-side interaction tools provided by MITRE (no modifications).
- **frames/**: Example frame data for system testing.
- **wolfssl/**: Crypto library examples and integrations.

## Setup and Requirements

### Environment Setup (Docker)
Ensure Docker is installed and running. First-time builds may take approximately 10 minutes:
```shell
cd decoder
docker build -t decoder .
```

### Python Environment Setup
Recommended to set up a Python virtual environment:

**Linux/Mac:**
```shell
python -m venv .venv
source .venv/bin/activate
pip install ./tools/
pip install -e ./design/
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install .\tools\
pip install -e .\design\
```

## Firmware Building
Build the decoder firmware using Docker:

```shell
docker run --rm -v ./build_out:/out -v ./:/decoder -v ../secrets:/secrets -e DECODER_ID=0xdeadbeef decoder
```

## Generating Secrets and Subscriptions
Create shared secrets for specified channels:

```shell
mkdir secrets
python -m ectf25_design.gen_secrets secrets/secrets.json 1 3 4
```

Create subscription updates:

```shell
python -m ectf25_design.gen_subscription secrets/secrets.json subscription.bin 0xDEADBEEF 32 128 1
```

## Flashing Firmware
Flash firmware to MAX78000 board using provided tools:

**Linux/Mac:**
```shell
python -m ectf25.utils.flash ./build_out/max78000.bin /dev/tty.usbmodemXXXX
```

**Windows:**
```powershell
python -m ectf25.utils.flash .\build_out\max78000.bin COMXX
```

## Host Tools

### Channel Listing
List active subscriptions on decoder:
```shell
python -m ectf25.tv.list /dev/tty.usbmodemXXXX
```

### Subscription Updates
Send subscription updates to decoder:
```shell
python -m ectf25.tv.subscribe subscription.bin /dev/tty.usbmodemXXXX
```

### Testing Decoder
Perform decoder tests with generated or provided frames:
```shell
python -m ectf25.utils.tester --port /dev/tty.usbmodemXXXX -s ./secrets/secrets.json rand -c 1 -f 64
```

## Running the System

### Start Uplink
Sends frames to the satellite:
```shell
python -m ectf25.uplink secrets/secrets.json localhost 2000 1:10:frames/x_c0.json
```

### Start Satellite
Broadcasts frames to all decoders:
```shell
python -m ectf25.satellite localhost 2000 localhost 1:2001
```

### Start TV
Receives satellite broadcast frames and interfaces with decoder:
```shell
python -m ectf25.tv.run localhost 2001 /dev/tty.usbmodemXXXX
```

## Support and Documentation
For further details, check the documentation provided in the `docs/` directory or contact the repository maintainers.

