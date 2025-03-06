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

# ****************** STACK PROTECTION AND SECURITY FLAGS ******************
PROJ_CFLAGS += -D_FORTIFY_SOURCE=3 -fstack-protector-strong -Wformat -Wformat-security -Werror=format-security
