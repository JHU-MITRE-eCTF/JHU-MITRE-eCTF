# Dockerfile for the 2025 eCTF
# Make any changes here to set up your build environment (e.g., installing crypto
# libraries, dependencies, the compiler for a different language)

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="Example Decoder Docker Container for the 2025 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
# do this first because it takes the longest
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gdb \
    gdb-multiarch \
    gcc-arm-none-eabi \
    binutils-arm-none-eabi \
    make \
    python3.10 \
    git \
    wget \
    libtool \
    texinfo \
    unzip    

# Install MSDK
RUN apt-get install -y unzip && \
    wget https://github.com/analogdevicesinc/msdk/archive/refs/tags/v2024_02.zip && \
    unzip v2024_02.zip && \
    rm -f v2024_02.zip

ENV MAXIM_PATH=/root/msdk-2024_02

WORKDIR /decoder

ENTRYPOINT ["bash", "-c", "mv /global.secrets/secrets*.bin /global.secrets/secrets.bin && dd if=/global.secrets/secrets.bin of=/out/secrets_decoder.bin bs=1 count=64 && cd /out && arm-none-eabi-objcopy -I binary -O elf32-littlearm -B arm secrets_decoder.bin secrets.o && arm-none-eabi-objcopy secrets.o --redefine-sym _binary_secrets_decoder_bin_start=secrets_bin_start  --redefine-sym _binary_secrets_decoder_bin_end=secrets_bin_end && cd /decoder && make release DECODER_ID=${DECODER_ID} && cp build/max78000.elf build/max78000.bin /out"]

# Sample run command:
# docker run -v ./decoder/:/decoder -v ./global.secrets:/global.secrets:ro -v ./deadbeef_build:/out -e DECODER_ID=0xdeadbeef build-decoder

# Zhong: for your convenience
# build docker:
# - `docker build -t decoder_new .`
# decoder_id is passed here as 0x12345678:
# - `docker run -v $(pwd)/decoder/:/decoder -v $(pwd)/global.secrets:/global.secrets:ro -v $(pwd)/12345678_build:/out -e DECODER_ID=0x12345678 decoder_new`