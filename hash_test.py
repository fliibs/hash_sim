from hash_sim import *
from multiprocessing import Pool, cpu_count
from sys import exit
from tqdm import tqdm 


def check_config(args):
    mask_0, mask_1, mask_2, sel_bit0, sel_bit1, mask_sel0, mask_sel1, addr_list = args
    hash_machine = NIUOCMHash(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, mask_sel0, mask_sel1, getattr(Config, f"hash_gran_{mode}_index"))
    for addr_list_elem in addr_list:
        res_bin_list = [0 for _ in range(3)]
        for elem in addr_list_elem:
            res_bin_list[hash_machine.hash_and(elem)] += 1
            
        if sum(1 for x in res_bin_list if x != 0) == 1:
            pass 
        else:
            return None
        
    print(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, res_bin_list)
    return hash_machine.get_mask_config()


if __name__ == '__main__':
    generator = ADDRGenerator(Config.start_address, Config.end_address, getattr(Config, f"hash_gran_{mode}"))
    addr_list = generator.get_gran_addr_list()
    
    task_args = []
    with open(f'output/output_{mode}.txt', 'r', encoding='utf-8') as f:
        for line in f:
            str_list = line.strip('[]\n').split(', ')
            int_list = [int(x) for x in str_list]
            int_list.append(addr_list)
            task_args.append(int_list)
        f.close()

    total = len(task_args)
    print(f"Total combinations: {total}")

    mask_list = []
    with Pool(cpu_count()) as p:
        for result in tqdm(p.imap_unordered(check_config, task_args, chunksize=100), total=total):
            if result is not None:
                mask_list.append(result)

    
    with open(f'output/output_{mode}_real.txt', 'w', encoding='utf-8') as f:
        for item in mask_list:
            f.write(str(item) + '\n')