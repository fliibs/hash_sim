import random

mode = '1K'
xbar_mode = 2048
global_mask = 0x92492498800

def bitwise_self_xor(n: int) -> int:
    bit_len = n.bit_length()
    result = 0
    for i in range(bit_len):
        bit = (n >> i) & 1
        result = result ^ bit 
    return result

MB = 2**20

class HashChecker():
    def __init__(self, start=0, tgt_num=3, xbar_mode=xbar_mode):
        self.start = start
        self.tgt_num = tgt_num
        self.addr_list = [{} for _ in range(tgt_num)]
        self.xbar_mode = xbar_mode
        self.mask = int(global_mask-self.xbar_mode)
        
    def mask_addr(self, addr):
        return bitwise_self_xor(addr&self.mask)
    
    def gen_ocm_addr(self, addr):
        # print(hex(self.mask), hex(addr), hex(addr&self.mask), self.mask_addr(addr)*self.xbar_mode)
        return (addr - self.start) & (0x7fffff-self.xbar_mode)
    
    def gen_ocm_addr_3m(self, addr):
        header = (addr >> 20) & 0x3f
        if header>=0b011000 and header < 0b011011:
            base = 0
            divd = 0
        elif header >= 0b011011 and header < 0b011110:
            base = 3*MB
            divd = 1
        elif header >= 0b011110 and header < 0b100001:
            base = 2*3*MB
            divd = 2
        elif header >= 0b100001 and header < 0b100100:
            base = 3*3*MB
            divd = 3
        elif header >= 0b100100 and header < 0b100111:
            base = 4*3*MB
            divd = 4
        elif header >= 0b100111 and header < 0b101010:
            base = 5*3*MB
            divd = 5
        else:
            print(hex(addr), hex(header))
            raise Exception()
        # print(hex(addr), hex(self.start), hex(base), hex(header), hex((0x7fffff-self.xbar_mode)), hex((addr - self.start - base)))
        return ((addr - self.start - base) & (0xfffff-self.xbar_mode))<<3 | divd
     
    def add_addr(self, addr, tgt_id, config=None):
        ocm_addr = self.gen_ocm_addr(addr)
        if ocm_addr not in self.addr_list[tgt_id].keys():
            self.addr_list[tgt_id][ocm_addr] = [addr, config]
            return 0
        else:
            if self.addr_list[tgt_id][ocm_addr][0] != addr:
                print(f"Address conflict: {hex(self.addr_list[tgt_id][ocm_addr][0]), self.addr_list[tgt_id][ocm_addr][1]} and {hex(addr)} for {hex(ocm_addr)} target ID {tgt_id}")
                return -1
            
    def add_addr_3m(self, addr, tgt_id, config=None):
        ocm_addr = self.gen_ocm_addr_3m(addr)
        if ocm_addr not in self.addr_list[tgt_id].keys():
            self.addr_list[tgt_id][ocm_addr] = [addr, config]
            return 0
        else:
            if self.addr_list[tgt_id][ocm_addr][0] != addr:
                print(f"Address conflict: {hex(self.addr_list[tgt_id][ocm_addr][0]), self.addr_list[tgt_id][ocm_addr][1]} and {hex(addr)} for {hex(ocm_addr)} target ID {tgt_id}")
                return -1
            
            

class NIUOCMHash():
    def __init__(self, mask_0=0, mask_1=0, mask_2=0, sel_bit0=0, sel_bit1=0 ,sel_bit_mask0=0, sel_bit_mask1=0, hash_index=[8, 11, 14]):
        self.mask_0        = mask_0   & 0b111
        self.mask_1        = mask_1   & 0b111
        self.mask_2        = mask_2   & 0b111
        self.sel_bit0      = sel_bit0 & 0b11111
        self.sel_bit1      = sel_bit1 & 0b11111
        self.sel_bit_mask0 = sel_bit_mask0 & 0b1
        self.sel_bit_mask1 = sel_bit_mask1 & 0b1
        self.first_index   = hash_index[0]
        self.second_index  = hash_index[1]
        self.third_index   = hash_index[2]
        self.hash_index    = hash_index
        
        if sel_bit0 >= 40: raise Exception()
        if sel_bit1 >= 40: raise Exception()
    
    def init_config(self, mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit_mask0, sel_bit_mask1, hash_index=[8, 11, 14]):
        self.mask_0        = mask_0   & 0b111
        self.mask_1        = mask_1   & 0b111
        self.mask_2        = mask_2   & 0b111
        self.sel_bit0      = sel_bit0 & 0b111111
        self.sel_bit1      = sel_bit1 & 0b111111
        self.sel_bit_mask0 = sel_bit_mask0 & 0b1
        self.sel_bit_mask1 = sel_bit_mask1 & 0b1
        self.first_index   = hash_index[0]
        self.second_index  = hash_index[1]
        self.third_index   = hash_index[2]
        self.hash_index    = hash_index
        
        if sel_bit0 >= 40: raise Exception()
        if sel_bit1 >= 40: raise Exception()
    
    def get_config(self):
        return [self.mask_0, self.mask_1, self.mask_2, self.sel_bit0, self.sel_bit1, self.sel_bit_mask0, self.sel_bit_mask1]
        return [self.mask_0, self.mask_1, self.mask_2, self.sel_bit0, self.sel_bit1, self.sel_bit_mask0, self.sel_bit_mask1, self.hash_index]
    
    def get_mask_config(self):
        mask = (self.mask_0<<self.first_index)|(self.mask_1<<self.second_index)|(self.mask_2<<self.third_index)|(self.sel_bit_mask0<<self.sel_bit0)|(self.sel_bit_mask1<<self.sel_bit1)
        return [hex(mask), hex(self.sel_bit0), hex(self.sel_bit1)]
    
    def hash_xor(self, address):
        addr_part0    = (address>>self.first_index)  & 0b111
        addr_part1    = (address>>self.second_index) & 0b111
        addr_part2    = (address>>self.third_index)  & 0b111
        sel_addr_bit0 = (address>>self.sel_bit0) & self.sel_bit_mask0
        sel_addr_bit1 = (address>>self.sel_bit1) & self.sel_bit_mask1
        
        tgt_id_xor0 = (addr_part0 ^ self.mask_0)
        tgt_id_xor1 = (addr_part1 ^ self.mask_1) 
        tgt_id_xor2 = (addr_part2 ^ self.mask_2)
        
        tgt_id =  tgt_id_xor0 + tgt_id_xor1 + tgt_id_xor2 + (sel_addr_bit1<<1)|sel_addr_bit0
        return tgt_id % 3
    
    def hash_and(self, address):
        addr_part0    = (address>>self.first_index)  & 0b111
        addr_part1    = (address>>self.second_index) & 0b111
        addr_part2    = (address>>self.third_index)  & 0b111
        sel_addr_bit0 = (address>>self.sel_bit0) & self.sel_bit_mask0
        sel_addr_bit1 = (address>>self.sel_bit1) & self.sel_bit_mask1
        
        tgt_id_xor0 = (addr_part0 & self.mask_0)
        tgt_id_xor1 = (addr_part1 & self.mask_1) 
        tgt_id_xor2 = (addr_part2 & self.mask_2)
        
        tgt_id =  tgt_id_xor0 + tgt_id_xor1 + tgt_id_xor2 + (sel_addr_bit1<<1)|sel_addr_bit0
        return tgt_id % 3
 
    
class NIUOCMHashOpt(NIUOCMHash):
    def __init__(self, mask_0=0, mask_1=0, mask_2=0, sel_bit0=0, sel_bit1=0, sel_bit2=0,sel_bit_mask0=0, sel_bit_mask1=0, sel_bit_mask2=0, hash_index=[8, 11, 14]):
        super().__init__(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit_mask0, sel_bit_mask1, hash_index)
        self.sel_bit2     = sel_bit2 & 0b11111
        self.sel_bit_mask2 = sel_bit_mask2 & 0b1
        self.reserve_list = None
        
    def hash_and(self, address):
        addr_part0    = (address>>self.first_index)  & 0b111
        addr_part1    = (address>>self.second_index) & 0b111
        addr_part2    = (address>>self.third_index)  & 0b111
        sel_addr_bit0 = (address>>self.sel_bit0) & self.sel_bit_mask0
        sel_addr_bit1 = (address>>self.sel_bit1) & self.sel_bit_mask1
        sel_addr_bit2 = (address>>self.sel_bit2) & self.sel_bit_mask2
        
        tgt_id_xor0 = (addr_part0 & self.mask_0)
        tgt_id_xor1 = (addr_part1 & self.mask_1) 
        tgt_id_xor2 = (addr_part2 & self.mask_2)
        
        tgt_id      =  tgt_id_xor0 + tgt_id_xor1 + tgt_id_xor2 + ((sel_addr_bit2<<2)|(sel_addr_bit1<<1)|sel_addr_bit0)
        # self.reserve_list = [tgt_id_xor0, tgt_id_xor1, tgt_id_xor2, ((sel_addr_bit2<<2)|(sel_addr_bit1<<1)|sel_addr_bit0), tgt_id % 3, self.get_config()]
        return tgt_id % 3
    
    def get_config(self):
        return [self.mask_0, self.mask_1, self.mask_2, self.sel_bit0, self.sel_bit1, self.sel_bit2, self.sel_bit_mask0, self.sel_bit_mask1, self.sel_bit_mask2]
    
    def get_mask_config(self):
        mask = (self.mask_0<<self.first_index)|(self.mask_1<<self.second_index)|(self.mask_2<<self.third_index)|(self.sel_bit_mask0<<self.sel_bit0)|(self.sel_bit_mask1<<self.sel_bit1)|(self.sel_bit_mask2<<self.sel_bit2)
        return [hex(mask), hex(self.sel_bit0), hex(self.sel_bit1), hex(self.sel_bit2)]
        
    def show(self):
        print(self.reserve_list)
        

class NIUOCMHashOpt3M(NIUOCMHash):
    def __init__(self, mask_0=0, mask_1=0, mask_2=0, sel_bit0=0, sel_bit1=0, sel_bit2=0, sel_bit3=0, sel_bit_mask0=0, sel_bit_mask1=0, sel_bit_mask2=0, sel_bit_mask3=0, hash_index=[8, 11, 14]):
        super().__init__(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit_mask0, sel_bit_mask1, hash_index)
        self.sel_bit2     = sel_bit2 & 0b11111
        self.sel_bit_mask2 = sel_bit_mask2 & 0b1
        
        self.sel_bit3     = sel_bit3 & 0b11111
        self.sel_bit_mask3 = sel_bit_mask3 & 0b1
        
        self.reserve_list = None
        
    def hash_and(self, address):
        addr_part0    = (address>>self.first_index)  & 0b111
        addr_part1    = (address>>self.second_index) & 0b111
        addr_part2    = (address>>self.third_index)  & 0b111
        sel_addr_bit0 = (address>>self.sel_bit0) & self.sel_bit_mask0
        sel_addr_bit1 = (address>>self.sel_bit1) & self.sel_bit_mask1
        sel_addr_bit2 = (address>>self.sel_bit2) & self.sel_bit_mask2
        sel_addr_bit3 = (address>>self.sel_bit3) & self.sel_bit_mask3
        
        sel_addr_bit0_3m = (address>>(self.sel_bit0-3)) & self.sel_bit_mask0
        sel_addr_bit1_3m = (address>>(self.sel_bit1-3)) & self.sel_bit_mask1
        sel_addr_bit2_3m = (address>>(self.sel_bit2-3)) & self.sel_bit_mask2
        
        tgt_id_xor0 = (addr_part0 & self.mask_0)
        tgt_id_xor1 = (addr_part1 & self.mask_1) 
        tgt_id_xor2 = (addr_part2 & self.mask_2)
        
        # tgt_id      =  tgt_id_xor0 + tgt_id_xor1 + tgt_id_xor2 + ((sel_addr_bit2<<2)|(sel_addr_bit1<<1)|sel_addr_bit0) - ((sel_addr_bit2_3m<<2)|(sel_addr_bit1_3m<<1)|sel_addr_bit0_3m)
        tgt_id      =  tgt_id_xor0 + tgt_id_xor1 + tgt_id_xor2 + ((sel_addr_bit2<<5)|(sel_addr_bit1<<4)|(sel_addr_bit0<<3)|(sel_addr_bit2_3m<<2)|(sel_addr_bit1_3m<<1)|(sel_addr_bit0_3m<<0))
        self.reserve_list = [hex(address), tgt_id_xor0, tgt_id_xor1, tgt_id_xor2, ((sel_addr_bit2<<2)|(sel_addr_bit1<<1)|sel_addr_bit0) + sel_addr_bit2_3m, tgt_id % 3, self.get_config()]
        return tgt_id % 3
    
    def get_config(self):
        return [self.mask_0, self.mask_1, self.mask_2, self.sel_bit0, self.sel_bit1, self.sel_bit2, self.sel_bit3, self.sel_bit_mask0, self.sel_bit_mask1, self.sel_bit_mask2, self.sel_bit_mask3]
    
    def get_mask_config(self):
        mask = (self.mask_0<<self.first_index)|(self.mask_1<<self.second_index)|(self.mask_2<<self.third_index)|(self.sel_bit_mask0<<self.sel_bit0)|(self.sel_bit_mask1<<self.sel_bit1)|(self.sel_bit_mask2<<self.sel_bit2)
        return [hex(mask), hex(self.sel_bit0), hex(self.sel_bit1), hex(self.sel_bit2)]
        
    def show(self):
        print(self.reserve_list)


class ADDRGenerator():
    def __init__(self, start, end, gran, xbar_mode=xbar_mode):
        self.start = start 
        self.end   = end 
        self.gran  = gran 
        self.xbar_mode  = xbar_mode
        self.mask = global_mask
        
    def get_addr_list(self):
        return [elem for elem in range(self.start, self.end+1, self.gran)]
    
    def get_gran_addr_list(self):
        # random_elem = random.choice(self.get_addr_list())
        return [[elem for elem in range(random_elem, random_elem+self.gran, 0x40)] for random_elem in self.get_addr_list()]
    
    def get_hash_addr_list(self):
        return [elem for elem in range(self.start, self.end+1, self.xbar_mode<<1)]
        
    def get_mask_addr_list(self, default=True):
        lst = []
        for elem in range(self.start, self.end+1, self.xbar_mode):
            mask_addr = elem & self.mask 
            if bitwise_self_xor(mask_addr)==default:
                lst.append(elem)
        return lst      





class Config:
    start_address       = 0x11800000
    end_address         = 0x129fffff
    # end_address         = start_address + 12*(2**20) - 1
    hash_gran_256       = 0x100
    hash_gran_256_index = [8, 11, 14]
    hash_gran_512       = 0x200
    hash_gran_512_index = [8, 11, 14]
    hash_gran_1K        = 0x400
    hash_gran_1K_index  = [8, 11, 14]
    hash_gran_2K        = 0x800
    hash_gran_2K_index  = [8, 11, 14]
    hash_gran_4K        = 0x1000
    hash_gran_4K_index  = [8, 11, 14]
    
    
if __name__ == '__main__':
    generator = ADDRGenerator(Config.start_address, Config.end_address, Config.hash_gran_4K)
    addr_list = generator.get_addr_list()
    print(len(addr_list)/3)
                            
                
        