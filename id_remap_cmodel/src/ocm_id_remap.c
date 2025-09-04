#include "../include/ocm_id_remap.h"

static uint32_t select_3base_for_addr(uint64_t addr_in) {
    uint32_t sel = 0;
    if(addr_in >=  M0 && addr_in < M1)      sel = 0;
    else if(addr_in >=  M1 && addr_in < M2) sel = 1;
    else if(addr_in >=  M2 && addr_in < M3) sel = 2;
    else if(addr_in >=  M3 && addr_in < M4) sel = 3;
    else if(addr_in >=  M4 && addr_in < M5) sel = 4;
    else if(addr_in >=  M5 && addr_in < M6) sel = 5;
    else assert(0);      
    return sel;
}

static uint32_t select_2base_for_addr(uint64_t addr_in) {
    uint32_t sel = 0;
    // fprintf(stderr, "select_2base_for_addr: addr_in =0x%lx, M0=0x%lx, M1=%lx, M2=0x%lx, M3=0x%lx, M4=0x%lx\n",addr_in,M0,M1,M2,M3,M4);
    if(addr_in >=  M0 && addr_in < M1)      sel = 0;
    else if(addr_in >=  M1 && addr_in < M2) sel = 1;
    else if(addr_in >=  M2 && addr_in < M3) sel = 2;
    else if(addr_in >=  M3 && addr_in < M4) sel = 3;
    else assert(0);      
    return sel;
}

static uint32_t adjust_addr_for_3bank(uint64_t addr_in, uint32_t xbar_hash_gran, uint32_t sel_base) {
    uint32_t addr_out   ;
    uint32_t high_part  ;
    uint32_t low_part   ;
    high_part = (addr_in & ((1ULL << 20) -1))  >> (xbar_hash_gran+1)        ;
    low_part  =  addr_in & ((1ULL << xbar_hash_gran) -1 )                   ;
    addr_out  = (sel_base << 19) |(high_part << xbar_hash_gran) |  low_part ; 
    return addr_out ;
}

static uint32_t adjust_addr_for_2bank(uint64_t addr_in, uint32_t xbar_hash_gran, uint32_t niu_hash_gran, uint32_t sel_base) {
    uint32_t sel_base_bit0 = 0;
    uint32_t sel_base_bit1 = 0;
    uint32_t addr_out         ;

    sel_base_bit0   = sel_base & 0b1                            ;
    sel_base_bit1   = (sel_base & 0b10) >> 1                    ;
    addr_out        = (addr_in & ~((1 << xbar_hash_gran) | (1 << niu_hash_gran))) | 
                      (sel_base_bit0 << xbar_hash_gran)         | 
                      (sel_base_bit1 << niu_hash_gran)          ; 
    
    // printf("adjust_addr_for_2bank def: sel_base_bit0 = 0x%lx, sel_base_bit1 = 0x%lx, sel_base_bit0<<xbar_hash_gran is 0x%lx, sel_base_bit1 << niu_hash_gran 0x%lx\n",sel_base_bit0 , sel_base_bit1 , (sel_base_bit0<<xbar_hash_gran), (sel_base_bit1 << niu_hash_gran));
    // printf("adjust_addr_for_2bank def: addr_out = 0x%lx\n",addr_out);
    return addr_out ;
}

static uint32_t get_hash_gran(uint64_t hash_mask) {
    uint32_t gran = 0;
    if(hash_mask & GRAN_256)      gran = 8    ;
    else if(hash_mask & GRAN_512) gran = 9    ;
    else if(hash_mask & GRAN_1K)  gran = 10   ;
    else if(hash_mask & GRAN_2K)  gran = 11   ;
    else assert(0); // must have one of these set
    return gran;
}

uint32_t ocm_id_remap(
    bool        hash_2_bank_en  ,
    bool        hash_3_bank_en  ,
    uint64_t    base_addr_0     ,
    uint64_t    addr_in         ,
    uint64_t    xbar_hash_mask  ,
    uint64_t    niu_hash_mask   ,
    bool        xbar_hash_en    ,
    uint8_t     hash_mode        // 0=2bank, 1=3bank
){
    /* Basic sanity asserts */
    assert((base_addr_0 & ~BIT_MASK_40) == 0)   ;
    assert((addr_in & ~BIT_MASK_40) == 0)       ;

    bool hash_disabled = ((hash_mode == 0) && !hash_2_bank_en) || ((hash_mode == 1) && !hash_3_bank_en) || (xbar_hash_en==0) ;
    
    // printf("hash_disable is %d\n",hash_disabled);
    // printf("(hash_mode == 0) && !hash_2_bank_en) is %d, ((hash_mode == 1) && !hash_3_bank_en) is %d, ~xbar_hash_en is %d \n",((hash_mode == 0) && !hash_2_bank_en), ((hash_mode == 1) && !hash_3_bank_en),~xbar_hash_en);

    uint32_t xbar_hash_gran ;
    uint32_t niu_hash_gran  ;

    xbar_hash_gran = get_hash_gran(xbar_hash_mask);
    niu_hash_gran  = get_hash_gran(niu_hash_mask) ;

     /* select base */
    uint32_t sel_base      = 0;

    uint32_t addr_out      = 0;
    uint64_t effective_addr= 0;
    uint32_t addr_out_hash = 0;


    if(hash_mode ==0) {
        sel_base        = select_2base_for_addr(addr_in)        ;
        effective_addr= addr_in - base_addr_0 - sel_base * R3M  ;
        
        // fprintf(stderr,"2BANK: sel_base = 0x%lx, effective_addr = 0x%lx\n",sel_base,effective_addr);

        if ((effective_addr & ~BIT_MASK_22) != 0) {
            // fprintf(stderr, "ERROR: effective_addr (0x%lx) exceeds 22-bit range; addr_in=0x%lx, base_addr_0=0x%lx, sel_base=%d, R3M=0x%lx\n", effective_addr, addr_in, base_addr_0, sel_base, R3M);
            assert(0);
        }

        if (effective_addr >= R3M) {
            // fprintf(stderr, "ERROR: effective_addr (0x%lx) is out of range [0, 0x%lx); addr_in=0x%lx, base_addr_0=0x%lx, sel_base=%d\n", effective_addr, R3M, addr_in, base_addr_0, sel_base);
            assert(0);
        }
        addr_out_hash   = adjust_addr_for_2bank(effective_addr, xbar_hash_gran, niu_hash_gran, sel_base);
    }
    else {
        sel_base        = select_3base_for_addr(addr_in)                                ;
        effective_addr         = addr_in - base_addr_0 - sel_base * R3M    ;
    
        if ((effective_addr & ~BIT_MASK_22) != 0) {
            // fprintf(stderr, "ERROR: effective_addr (0x%lx) exceeds 22-bit range; addr_in=0x%lx, base_addr_0=0x%lx, sel_base=%d, R3M=0x%lx\n", effective_addr, addr_in, base_addr_0, sel_base, R3M);
            assert(0);
        }

        if (effective_addr >= R3M) {
            // fprintf(stderr, "ERROR: effective_addr (0x%lx) is out of range [0, 0x%lx); addr_in=0x%lx, base_addr_0=0x%lx, sel_base=%d\n", effective_addr, R3M, addr_in, base_addr_0, sel_base);
            assert(0);
        }
        addr_out_hash   = adjust_addr_for_3bank(effective_addr,xbar_hash_gran,sel_base) ;
    }

    addr_out = hash_disabled ? effective_addr : addr_out_hash                                ;
    // printf("addr_out = %0lx,addr_out_hash = %0lx\n",addr_out,addr_out_hash);
    return addr_out;
}