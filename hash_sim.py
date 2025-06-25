import random

mode = '4K'

class HashChecker():
    def __init__(self, start=0, tgt_num=3):
        self.start = start
        self.tgt_num = tgt_num
        self.addr_list = [{} for _ in range(tgt_num)]
    
    def gen_ocm_addr(self, addr):
        return (addr - self.start) & 0xffffff
    
    def add_addr(self, addr, tgt_id, config=None):
        ocm_addr = self.gen_ocm_addr(addr)
        if ocm_addr not in self.addr_list[tgt_id].keys():
            self.addr_list[tgt_id][ocm_addr] = addr
            return 0
        else:
            if self.addr_list[tgt_id][ocm_addr] != addr:
                print(f"Address conflict: {hex(self.addr_list[tgt_id][ocm_addr])} and {hex(addr)} for {hex(ocm_addr)} target ID {tgt_id}")
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
        mask = (self.mask_0<<self.first_index)|(self.mask_1<<self.second_index)|(self.mask_2<<self.third_index)|(self.sel_bit_mask0<<self.sel_bit0)|(self.sel_bit_mask1<<self.sel_bit1)
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
        self.reserve_list = [tgt_id_xor0, tgt_id_xor1, tgt_id_xor2, ((sel_addr_bit2<<2)|(sel_addr_bit1<<1)|sel_addr_bit0), tgt_id % 3, self.get_config()]
        return tgt_id % 3
    
    def get_config(self):
        mask = (self.mask_0<<self.first_index)|(self.mask_1<<self.second_index)|(self.mask_2<<self.third_index)|(self.sel_bit_mask0<<self.sel_bit0)|(self.sel_bit_mask1<<self.sel_bit1)
        return [self.mask_0, self.mask_1, self.mask_2, self.sel_bit0, self.sel_bit1, self.sel_bit2, self.sel_bit_mask0, self.sel_bit_mask1, self.sel_bit_mask2]
    
    def get_mask_config(self):
        mask = (self.mask_0<<self.first_index)|(self.mask_1<<self.second_index)|(self.mask_2<<self.third_index)|(self.sel_bit_mask0<<self.sel_bit0)|(self.sel_bit_mask1<<self.sel_bit1)
        return [hex(mask), hex(self.sel_bit0), hex(self.sel_bit1), hex(self.sel_bit2)]
        
    def show(self):
        print(self.reserve_list)
        

class ADDRGenerator():
    def __init__(self, start, end, gran):
        self.start = start 
        self.end   = end 
        self.gran  = gran 
        
    def get_addr_list(self):
        return [elem for elem in range(self.start, self.end+1, self.gran)]
    
    def get_gran_addr_list(self):
        # random_elem = random.choice(self.get_addr_list())
        return [[elem for elem in range(random_elem, random_elem+self.gran, 0x40)] for random_elem in self.get_addr_list()]
            


class Config:
    start_address       = 0x11800000
    end_address         = 0x12ffffff
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
                            
                
        