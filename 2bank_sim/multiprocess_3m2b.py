from hash_sim import *
from multiprocessing import Pool, cpu_count
from tqdm import tqdm 
import random 
import os

addr_list = []
gran_addr_list = []

def check_config(args):
    args_res = (1 << top_range)+ niu_mode 
    print(f'Checking mask: {hex(args_res)}')
    hash_machine = NIUOCMHashOpt3M2B(args_res)
    checker = HashChecker(generator.start)
    res_bin_list = [0 for _ in range(2)]
    for elem in addr_list:
        tgt_id = hash_machine.hash_xor(elem)
        res_bin_list[tgt_id] += 1
        if checker.add_addr_2m(elem, tgt_id, hash_machine.reserve_list)==-1: 
            hash_machine.show()
            return None

    # print(res_bin_list)
    
    if len(set(res_bin_list)) == 1:
        return hash_machine.get_config()
    
    return None


def check_gran_config(args):
    hash_machine = NIUOCMHashOpt3M2B(args)
    for addr_list_elem in gran_addr_list:
        res_bin_list = [0 for _ in range(2)]
        for elem in addr_list_elem:
            tgt_id = hash_machine.hash_xor(elem)
            res_bin_list[tgt_id] += 1
            
        if sum(1 for x in res_bin_list if x != 0) == 1: pass 
        else:                                           return None
        
    # print(mask_0, mask_1, mask_2, res_bin_list)
    return hash_machine.get_config()


if __name__ == '__main__':
    generator = ADDRGenerator(Config.start_address, Config.end_address, getattr(Config, f"hash_gran_{mode}"))
    addr_list = generator.get_mask_addr_list()
    gran_addr_list = generator.get_gran_addr_list()
    

    #=====================================================
    # process in range
    #=====================================================
    top_range  = math.ceil(math.log2(xbar_mode)) + 1
    print(f"Top range: {top_range} bits")
    population = range(0, 2**(40-top_range))
    task_args  = random.sample(population, 1)

    total = len(task_args)
    print(f"Total combinations: {total}")
    mask_list = []
    for args in task_args:
        # print(hex(args))
        result = check_config(args)
        if result is not None:
            mask_list.append(result)

    output_dir = 'output2'
    os.makedirs(output_dir, exist_ok=True)

    with open(f'output2/output_{int(xbar_mode/2)}.txt', 'w') as f:
        for item in mask_list:
            f.write(hex(item) + '\n')   

    #=====================================================
    # process in gran
    #=====================================================
    total = len(mask_list)
    print(f"Total combinations in Gran: {total}")
    
    gran_mask_list = []
    with Pool(cpu_count()) as p:
        for result in tqdm(p.imap_unordered(check_gran_config, mask_list, chunksize=100), total=total):
            if result is not None:
                gran_mask_list.append(result)

    
    with open(f'output2/output_{int(xbar_mode/2)}_real.txt', 'w', encoding='utf-8') as f:
        for item in gran_mask_list:
            f.write(hex(item) + '\n')