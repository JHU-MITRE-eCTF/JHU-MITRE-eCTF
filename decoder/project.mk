# This file can be used to set build configuration
# variables.  These variables are defined in a file called 
# "Makefile" that is located next to this one.

# For instructions on how to use this system, see
# https://analog-devices-msdk.github.io/msdk/USERGUIDE/#build-system

# **********************************************************

# This example is only compatible with the FTHR board,
# so we override the BOARD value to hard-set it.
override BOARD=FTHR_RevA
MFLOAT_ABI=soft

IPATH+=../deployment
IPATH+=inc/
VPATH+=src/
PROJ_OBJS+=/out/secrets.o

# ****************** eCTF Bootloader *******************
# DO NOT REMOVE
LINKERFILE=firmware.ld
STARTUPFILE=startup_firmware.S
ENTRY=firmware_startup

# ****************** eCTF Crypto Example *******************
PROJ_CFLAGS += -DWOLFSSL_USE_OPTIONS_H
PROJ_CFLAGS += -DHAVE_ED25519 -DWOLFSSL_SHA512 -DHAVE_AESGCM
PROJ_CFLAGS += -DWC_RSA_BLINDING -DECC_TIMING_RESISTANT -DTFM_TIMING_RESISTANT

# ****************** STACK PROTECTION AND SECURITY FLAGS ******************
PROJ_CFLAGS += -D_FORTIFY_SOURCE=3 -fstack-protector-all -mstack-protector-guard=global -Wformat -Wformat-security -Werror=format-security
