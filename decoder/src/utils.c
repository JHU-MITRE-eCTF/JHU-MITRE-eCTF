#include "utils.h"
#include "max78000.h"
#include "mxc_sys.h"
#include "flc.h"
#include "string.h"
#include <stddef.h>
#include "mxc_delay.h"


#define RNG_STATE_ADDR 0x10042000
// Global state for xorshift32
#define SEED_REFRESH_INTERVAL 50 // Refresh seed after 50 calls
static uint32_t random_state = 0;
static uint32_t call_counter = 0;

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
 * @brief xorshift32: serve as simple random number generator
 *
 * @param state
 * @return uint32_t
 */
uint32_t xorshift32(uint32_t *state) {
    if (state == NULL || *state == 0) {
        // The caller violated this function's contract
        HALT_AND_CATCH_FIRE();
    }

    // Xorshift32 operations
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;

    return *state;
}

/**
 * @brief get_random_delay_us_faster
 *
 * @param max_delay_us
 * @return void
 */
void get_random_delay_us_faster(uint32_t max_delay_us) {
    if (call_counter % SEED_REFRESH_INTERVAL == 0 || random_state == 0) {
        // Seed refreshed from TRNG
        rng_get_trng_data((uint8_t *)&random_state, sizeof(random_state));
    }
    call_counter++;
    uint32_t rand_delay_us = xorshift32(&random_state) % max_delay_us;
    MXC_Delay(rand_delay_us);
}

/**
 * @brief get_random_delay_us
 *
 * @param max_delay_us
 * @return void
 */
void get_random_delay_us(uint32_t max_delay_us) {
    uint32_t random_seed = 0;
    rng_get_trng_data((uint8_t *)&random_seed, sizeof(random_seed));
    uint32_t random_value = xorshift32(&random_seed);
    uint32_t rand_delay_us = random_value % max_delay_us;
    MXC_Delay(rand_delay_us);
}


void disable_i2c() {
    MXC_GCR->pclkdis0 |= MXC_F_GCR_PCLKDIS0_I2C0;  // Disable I2C0
    MXC_GCR->pclkdis0 |= MXC_F_GCR_PCLKDIS0_I2C1;  // Disable I2C1
}

void disable_irq(void) {
    __disable_irq();  // Disables all interrupts
    // Disable all individual interrupts that can be disabled
    for (IRQn_Type irq = 0; irq < MXC_IRQ_EXT_COUNT; irq++) {
        NVIC_DisableIRQ(irq);  // Disable specific IRQ
    }
}

void disable_cache(void) {
    MXC_ICC0->ctrl &= ~MXC_F_ICC_CTRL_EN;  // Disable Instruction Cache 0
    MXC_ICC1->ctrl &= ~MXC_F_ICC_CTRL_EN;  // Disable Instruction Cache 1
}
