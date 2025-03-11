/**
 * @file util.h
 */
#pragma once

#include <stdint.h>

// Zhong: Secure wipe
// Add secure memset zero macro (place near top after includes)
#define secure_wipe(buf, len) do { \
    volatile uint8_t *p = (volatile uint8_t *)(buf); \
    size_t _len = (len); \
    while (_len--) *p++ = 0; \
} while(0)

/**
 * @brief Called when hardware tampering is detected
 * 
 * Macro used when the system is detected to be in an unstable state
 * and cannot be recovered. This is only called when a hardware issue
 * or unreachable system state is detected, and should never be
 * possible to reach during normal operation.
 */
#define HALT_AND_CATCH_FIRE() FI_PROTECT_0; do_spin_forever(); FI_PROTECT_2;

/**
 * @brief Delay for a random amount of time
 * 
 * Delay for a random amount of time between 0 and 5 seconds
 */
#define MAX_DELAY() get_random_delay_us(5000000);


/**
 * @brief Copy buffers with protection against fault injections
 * 
 * ASSERT: if the buffer doesn't match the copied data, something went horribly wrong (like a hardware fault)
 * Halt and catch fire if so.
 */
#define SECURE_MEMCPY(dst, src, len) do {        \
      memcpy(dst, src, len);                     \
      UTIL_ASSERT(memcmp(dst, src, len) == 0);   \
      get_random_delay_us_faster(1000);                       \
      UTIL_ASSERT(memcmp(dst, src, len) == 0);   \
    } while (0)

/**
 * @brief Assert but with fault injection protections
 */
#define SEC_ASSERT(x) do {         \
     UTIL_ASSERT(x);               \
     get_random_delay_us_faster(500);          \
     UTIL_ASSERT(x);               \
    } while (0)

/**
 * @brief Assert but with fault injection protections
 */
#define SEC_CHECK(x) do {         \
     UTIL_ASSERT(x);               \
     UTIL_ASSERT(x);               \
} while (0)

/**
 * @brief Assert and working if failed
 */
#define UTIL_ASSERT(x)             \
    do {                           \
        if (!(x)) {                \
            HALT_AND_CATCH_FIRE(); \
        }                          \
    } while (0)

/**
 * @brief Macros for fault injection prevention
 * 
 * Equivalent to a bunch of while(1);
 */
#define FI_PROTECT_0 __asm volatile( "1: ");  FI_PROTECT_1 FI_PROTECT_1
#define FI_PROTECT_1 FI_PROTECT_2 FI_PROTECT_2
#define FI_PROTECT_2 FI_PROTECT_3 FI_PROTECT_3
#define FI_PROTECT_3 FI_PROTECT_4 FI_PROTECT_4
#define FI_PROTECT_4 FI_PROTECT_5 FI_PROTECT_5
#define FI_PROTECT_5 __asm volatile( "b 1b; b 1b;" );

/**
 * @brief Spin forever
 * 
 */
void do_spin_forever();

/**
 * @brief Initialize the true random number generator
 * 
 */
void rng_init();

/**
 * @brief Delay for a random amount of time
 * 
 * Delay for a random amount of time between 0 and max_delay_us
 */
void get_random_delay_us(uint32_t max_delay_us);

/**
 * @brief Delay for a random amount of time
 * 
 * Delay for a random amount of time between 0 and max_delay_us
 */
void get_random_delay_us_faster(uint32_t max_delay_us);


#include "board.h"
#include "mxc_delay.h"
#include "mxc_device.h"
#include "mxc_sys.h"
#include "i2c.h"
#include "nvic_table.h"
#include "icc_regs.h"
#include "gcr_regs.h"

/** 
 * @brief disables unused i2c peripheral
 * @author Liz Grzyb
 **/
void disable_i2c();

/** 
 * @brief disables unused irq peripheral
 * @author Liz Grzyb
 **/
void disable_irq(void);

/** 
 * @brief disables cache
 * @author Liz Grzyb
 **/
void disable_cache(void);
