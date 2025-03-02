#include "utils.h"
#include "max78000.h"
#include "mxc_sys.h"
#include "flc.h"
#include "string.h"
#include <stddef.h>
#include "mxc_delay.h"


#define RNG_STATE_ADDR 0x10042000
#define RNG_BUFFER_LEN 64

#define MXC_F_TRNG_REVB_STATUS_RDY_POS                 0 /**< STATUS_RDY Position */
#define MXC_F_TRNG_REVB_STATUS_RDY                     ((uint32_t)(0x1UL << MXC_F_TRNG_REVB_STATUS_RDY_POS)) /**< STATUS_RDY Mask */

#ifdef __cplusplus
#define __I volatile
#else
#define __I volatile const
#endif
#define __O volatile
#define __IO volatile

typedef struct {
    __IO uint32_t ctrl;                 /**< <tt>\b 0x00:</tt> TRNG_REVB CTRL Register */
    __IO uint32_t status;               /**< <tt>\b 0x04:</tt> TRNG_REVB STATUS Register */
    __I  uint32_t data;                 /**< <tt>\b 0x08:</tt> TRNG_REVB DATA Register */
} mxc_trng_revb_regs_t;

typedef struct {
    __IO uint32_t ctrl;                 /**< <tt>\b 0x00:</tt> TRNG CTRL Register */
    __IO uint32_t status;               /**< <tt>\b 0x04:</tt> TRNG STATUS Register */
    __I  uint32_t data;                 /**< <tt>\b 0x08:</tt> TRNG DATA Register */
} mxc_trng_regs_t;


void do_spin_forever() {
    volatile int tmp = 1;
    while (tmp);
    __builtin_unreachable();
}

/**
 * @brief Initialize the rng module
 */
uint8_t *rng_key;

void rng_init() {
    // set RNG key pointer
    rng_key = (uint8_t*)RNG_STATE_ADDR;

    // Enable TRNG
    MXC_SYS_ClockEnable(MXC_SYS_PERIPH_CLOCK_TRNG);

    // Make sure flash is accessible
    while (MXC_FLC_Init() != E_NO_ERROR) {}
}

/**
 * @brief Get data from the hardware True RNG
 * 
 * @param trng trng pointer
 * @return random data 
 */
int rng_trng_int(mxc_trng_revb_regs_t *trng)
{
    while (!(trng->status & MXC_F_TRNG_REVB_STATUS_RDY)) {}

    return (int)trng->data;
}

/**
 * @brief Fills up a buffer with random data
 * 
 * @param data buffer pointer
 * @param len length of buffer
 */
void rng_get_trng_data(uint8_t *data, uint32_t len)
{
    unsigned int i, temp;

    if (data == NULL) {
        // The caller violated this function's contract
        // This can only happen due to a hardware fault
        HALT_AND_CATCH_FIRE();
    }

    for (i = 0; (i + 3) < len; i += 4) {
        temp = rng_trng_int((mxc_trng_revb_regs_t *)MXC_TRNG);
        memcpy(&(data[i]), (uint8_t *)(&temp), 4);
    }

    if (len & 0x03) {
        temp = rng_trng_int((mxc_trng_revb_regs_t *)MXC_TRNG);
        memcpy(&(data[i]), (uint8_t *)(&temp), len & 0x03);
    }
}

/**
 * @brief xorshift64: serve as simple random number generator
 *
 * @param state
 * @return uint64_t
 */
uint64_t xorshift64(uint8_t *state) {
  if (state == NULL) {
    // The caller violated this function's contract
    HALT_AND_CATCH_FIRE();
  }
  // Convert uint8_t[8] state to a uint64_t
  uint64_t x;
  memcpy(&x, state, sizeof(x)); // Safe for strict aliasing

  // Xorshift64 operations
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;

  // Convert uint64_t back to uint8_t[8] state
  memcpy(state, &x, sizeof(x)); // Safe for strict aliasing

  return x;
}

/**
 * @brief get_random_delay_us
 *
 * @param max_delay_us
 * @return void
 */
void get_random_delay_us(uint64_t max_delay_us) {
    uint8_t rng_state[RNG_BUFFER_LEN] = {0};
    rng_get_trng_data(rng_state, RNG_BUFFER_LEN);
    uint64_t rand_delay_us = xorshift64(rng_state) % max_delay_us;
    // MXC_DELAY_USEC(rand_delay_us);
    MXC_Delay((uint32_t)rand_delay_us);
    // delay_us((uint32_t)rand_delay_us);
}


// /**
//  * @brief Get Von Neuman whitened random data of RNG_BUFFER_LEN
//  * 
//  * @param data buffer pointer
//  */
// void rng_get_unbiased_trng(uint8_t *data) {
//     uint8_t stream[RNG_BUFFER_LEN*4]; // Generate 4*64 bytes to reduce chance of later overhead

//     uint8_t current_byte = 0;
//     uint8_t bits_generated = 0;
//     size_t buffer_idx = 0;

//     while (buffer_idx < RNG_BUFFER_LEN) {
//         rng_get_trng_data(stream, sizeof(stream)); 

//         for (uint32_t i = 0; i < sizeof(stream); i++) {
//             for (uint32_t bit = 0; bit < 8; bit+=2, stream[i] >>=2) {
//                 uint8_t bit1 = (stream[i] >> 1);
//                 uint8_t bit2 = stream[i];

//                 uint8_t diff = (bit1 ^ bit2) & 1;

//                 if (diff) {
//                     current_byte <<= 1;
//                     current_byte |= (bit1 & 1);
//                     bits_generated++;

//                     if (bits_generated == 8) {
//                         data[buffer_idx] = current_byte;
                        
//                         bits_generated = 0;
//                         current_byte = 0;
//                         buffer_idx += 1;

//                         if (buffer_idx >= RNG_BUFFER_LEN) {
//                             return;
//                         }
//                     }
//                 } 
//             }
//         }
//     }
// }

// /*
//  * @brief delay_us
//  *
//  * @param delay_us
//  */
// void delay_us(uint32_t delay) {
//   if (delay <= 0) { 
//     // The caller violated this function's contract
//     HALT_AND_CATCH_FIRE();
//   }
//   uint32_t delay_ticks = (SystemCoreClock / 1000000) * delay - 1;
//   SysTick->LOAD = delay_ticks;
//   SysTick->VAL = 0;
//   SysTick->CTRL = SysTick_CTRL_ENABLE_Msk | SysTick_CTRL_CLKSOURCE_Msk;
//   while (!(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk));
//   SysTick->CTRL = 0;
// }



// void secure_delay_and_recover(void) {
//     // Configure SysTick for 5-second delay (adjust for clock speed)
//     SysTick->LOAD = 5000000 - 1;  // 5s @ 1 MHz
//     SysTick->VAL = 0;
//     SysTick->CTRL = SysTick_CTRL_ENABLE_Msk;

//     // FI-resistant delay loop
//     while (!(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk)) {
//         // Redundant branches to resist instruction skipping
//         __asm volatile("nop; nop; b 1f; 1: nop; nop;");
//     }

//     SysTick->CTRL = 0; // Disable timer

//     // If instability persists, reset and repeat
//     if (!check_system_stable()) {
//         NVIC_SystemReset(); // Hardware reset
//     }
// }

// void secure_delay(uint64_t ms) {
//     // Configure a hardware timer (e.g., SysTick)
//     SysTick->LOAD = (SystemCoreClock / 1000) * ms - 1;
//     SysTick->VAL = 0;
//     /*
//      * SysTick_CTRL_CLKSOURCE_Msk : Use core's clock
//      * SysTick_CTRL_ENABLE_Msk    : Enable SysTick
//      * SysTick_CTRL_TICKINT_Msk   : Active the SysTick interrupt on the NVIC
//      */
//     SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;

//     // FI-resistant wait
//     while (!(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk)) {
//         __asm volatile("nop; nop; b 1f; 1: nop; nop;");
//     }

//     SysTick->CTRL = 0;  // Disable timer
// }