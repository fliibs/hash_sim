from hash_sim import *
import math

mask = 0x9249249400

start_address       = 0x11800000
# end_address         = 0x12ffffff

addr_0 = start_address
addr_1 = start_address + 1*MB

real_mode = 1024


hasher = NIUOCMHashOpt3M(
    mask_0 = 0,
    mask_1 = 0,
    mask_2 = 0,
    sel_bit0 = 23,
    sel_bit1 = 24,
    sel_bit2 = 25,
    sel_bit3 = 22,
    sel_bit_mask0 = 1,
    sel_bit_mask1 = 1,
    sel_bit_mask2 = 1,
    sel_bit_mask3 = 1
)

def bitwise_self_xor(n: int) -> int:
    bit_len = n.bit_length()
    result = 0
    for i in range(bit_len):
        bit = (n >> i) & 1
        result = result ^ bit 
    return result




checker = HashChecker(start=start_address, xbar_mode =real_mode)


def cal_addr(addr):
    xbar_mask = addr & mask
    noe = checker.gen_ocm_addr_3m(addr)
    print(hex(noe), bitwise_self_xor(xbar_mask), hasher.hash_and(addr), hex(addr))


cal_addr(addr_0)
cal_addr(addr_1)


# generator = ADDRGenerator(Config.start_address, Config.end_address, getattr(Config, f"hash_gran_{mode}"))
# addr_list_true = generator.get_mask_addr_list(True)
# addr_list_false = generator.get_mask_addr_list(False)

# print(len(addr_list_true), len(addr_list_false))