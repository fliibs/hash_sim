import random
import math 

mode = '256'
xbar_mode = 1024
global_mask = 0x92492498400
niu_mode  = 512

# xbar_mode = 512
# global_mask = 0x92492498200
# niu_mode  = 256

# xbar_mode = 2048
# global_mask = 0x92492498800
# niu_mode  = 1024

top_range  = math.ceil(math.log2(niu_mode)) + 1

def bitwise_self_xor(n: int) -> int:
    bit_len = n.bit_length()
    result = 0
    for i in range(bit_len):
        bit = (n >> i) & 1
        result = result ^ bit 
    return result

MB = 2**20

class HashChecker():
    def __init__(self, start=0, tgt_num=2, xbar_mode=xbar_mode,niu_mode = niu_mode):
        self.start      = start
        self.tgt_num    = tgt_num
        self.addr_list  = [{} for _ in range(tgt_num)]
        self.xbar_mode  = xbar_mode
        self.niu_mode   = niu_mode
    
    def gen_ocm_addr(self, addr):
        return (addr - self.start) & (0x7fffff-self.xbar_mode)
    
    def gen_ocm_addr_2m(self, addr):
        # print (f'self.xbar_mode {self.xbar_mode}, self.niu_mode {self.niu_mode}')
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
        else:
            print(hex(addr), hex(header))
            raise Exception()
        return ((addr - self.start - base) & (0x3fffff-self.xbar_mode -self.niu_mode))<<3 | divd
     
    def add_addr_2m(self, addr, tgt_id, config=None):
        ocm_addr = self.gen_ocm_addr_2m(addr)
        if ocm_addr not in self.addr_list[tgt_id].keys():
            self.addr_list[tgt_id][ocm_addr] = [addr, config]
            return 0
        else:
            if self.addr_list[tgt_id][ocm_addr][0] != addr:
                print(f"Address conflict: {hex(self.addr_list[tgt_id][ocm_addr][0]), self.addr_list[tgt_id][ocm_addr][1]} and {hex(addr)} for {hex(ocm_addr)} target ID {tgt_id}")
                # print(hex(ocm_addr))
                return -1

class NIUOCMHashOpt3M2B():
    def __init__(self,mask):
        self.mask         = mask 
        self.reserve_list = None    

    def get_config(self):
        return self.mask

    def get_mask_config(self):
        return [hex(self.mask)]  
    
    def hash_xor(self, address):
        addr_masked         = address & self.mask
        tgt_id              = bitwise_self_xor(addr_masked)
        self.reserve_list   = [hex(address), hex(addr_masked), tgt_id, self.get_config()]
        return tgt_id

    def show(self):
        print(self.reserve_list)

class ADDRGenerator():
    def __init__(self, start, end, gran, xbar_mode=xbar_mode):
        self.start      = start 
        self.end        = end 
        self.gran       = gran 
        self.xbar_mode  = xbar_mode
        self.mask       = global_mask
        self.niu_mode   = niu_mode
        
    def get_addr_list(self):
        return [elem for elem in range(self.start, self.end+1, self.gran)]
    
    def get_gran_addr_list(self):
        return [[elem for elem in range(random_elem, random_elem+self.gran, 0x40)] for random_elem in self.get_addr_list()]
    
    def get_hash_addr_list(self):
        return [elem for elem in range(self.start, self.end+1, self.xbar_mode<<1)]
        
    def get_mask_addr_list(self, default=True):
        lst = []
        # for elem in range(self.start, self.end+1, self.xbar_mode):
        for elem in range(self.start, self.end+1, self.niu_mode):
            mask_addr = elem & self.mask 
            if bitwise_self_xor(mask_addr)==default:
                lst.append(elem)
        return lst      

class Config:
    start_address       = 0x11800000
    end_address         = 0x123fffff
    hash_gran_256       = 0x100
    hash_gran_512       = 0x200
    hash_gran_1K        = 0x400
    hash_gran_2K        = 0x800
    hash_gran_4K        = 0x1000
    
if __name__ == '__main__':
    generator = ADDRGenerator(Config.start_address, Config.end_address, Config.hash_gran_4K)
    addr_list = generator.get_addr_list()
    print(len(addr_list)/3)
                            
                
        