from hash_sim import *
from multiprocessing import Pool, cpu_count
from tqdm import tqdm 

addr_list = []
gran_addr_list = []

def check_config(args):
    mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit2, mask_sel0, mask_sel1, mask_sel2 = args
    hash_machine = NIUOCMHashOpt(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit2, mask_sel0, mask_sel1, mask_sel2, getattr(Config, f"hash_gran_{mode}_index"))
    checker = HashChecker(generator.start)
    res_bin_list = [0 for _ in range(3)]
    for elem in addr_list:
        tgt_id = hash_machine.hash_and(elem)
        res_bin_list[tgt_id] += 1
        if checker.add_addr(elem, tgt_id, hash_machine.reserve_list)==-1: 
            hash_machine.show()
            return None
        
    if len(set(res_bin_list)) == 1:
        return hash_machine.get_config()
    return None


def check_gran_config(args):
    mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit2, mask_sel0, mask_sel1, mask_sel2 = args
    hash_machine = NIUOCMHashOpt(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit2, mask_sel0, mask_sel1, mask_sel2, getattr(Config, f"hash_gran_{mode}_index"))
    for addr_list_elem in gran_addr_list:
        res_bin_list = [0 for _ in range(3)]
        for elem in addr_list_elem:
            tgt_id = hash_machine.hash_and(elem)
            res_bin_list[tgt_id] += 1
            
        if sum(1 for x in res_bin_list if x != 0) == 1: pass 
        else:                                           return None
        
    # print(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, res_bin_list)
    return hash_machine.get_config()


if __name__ == '__main__':
    generator = ADDRGenerator(Config.start_address, Config.end_address, getattr(Config, f"hash_gran_{mode}"))
    addr_list = generator.get_addr_list()
    gran_addr_list = generator.get_gran_addr_list()
    

    #=====================================================
    # process in range
    #=====================================================
    task_args = [
        (m0, m1, m2, b0, b1, b2, ms0, ms1, ms2)
        for m0 in range(8)
        for m1 in range(8)
        for m2 in range(8)
        for b0 in range(23,24)
        for b1 in range(24,25)
        for b2 in range(25,26)
        for ms0, ms1, ms2 in [(1,1,1)]
    ]

    total = len(task_args)
    print(f"Total combinations: {total}")

    mask_list = []
    # with Pool(cpu_count()) as p:
    #     for result in tqdm(p.imap_unordered(check_config, task_args, chunksize=100), total=total):
    #         if result is not None:
    #             mask_list.append(result)
    
    for args in task_args:
        result = check_config(args)
        if result is not None:
            mask_list.append(result)

    # print("Balanced configs found:", mask_list)
    with open(f'output/output_{mode}.txt', 'w') as f:
        for item in mask_list:
            f.write(str(item) + '\n')
            
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

    
    with open(f'output/output_{mode}_real.txt', 'w', encoding='utf-8') as f:
        for item in gran_mask_list:
            f.write(str(item) + '\n')