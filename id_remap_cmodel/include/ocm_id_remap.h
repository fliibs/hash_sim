#ifndef OCM_ID_REMAP_H
#define OCM_ID_REMAP_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#define BIT_MASK_40 ((1ULL << 40) - 1	)
#define BIT_MASK_22 ((1ULL << 22) - 1	)
#define GRAN_256  	(1ULL << 8			)
#define GRAN_512  	(1ULL << 9			)
#define GRAN_1K  	(1ULL << 10			)
#define GRAN_2K  	(1ULL << 11			)
/* EXD_3M: example expected max (3M-like). Keep as sum of 2^21 + 2^20 as before */
#define R3M ((1ULL << 21) + (1ULL << 20))
#define M0  0X11800000ULL
#define M1 (M0+R3M*1)
#define M2 (M0+R3M*2)
#define M3 (M0+R3M*3)
#define M4 (M0+R3M*4)
#define M5 (M0+R3M*5)		
#define M6 (M0+R3M*6)

uint32_t ocm_id_remap(
    bool        hash_2_bank_en  ,
    bool        hash_3_bank_en  ,
    uint64_t    base_addr_0     ,
    uint64_t    addr_in         ,
    uint64_t    xbar_hash_mask  ,
    uint64_t    niu_hash_mask   ,
    bool        xbar_hash_en    ,
    uint8_t     hash_mode 
);

static uint32_t select_3base_for_addr(uint64_t addr_in);

static uint32_t select_2base_for_addr(uint64_t addr_in);

static uint32_t adjust_addr_for_3bank(uint64_t addr_in, uint32_t xbar_hash_gran, uint32_t sel_base);

static uint32_t adjust_addr_for_2bank(uint64_t addr_in, uint32_t xbar_hash_gran, uint32_t niu_hash_gran, uint32_t sel_base);
#endif // OCM_ID_REMAP_H