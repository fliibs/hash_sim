from hash_sim import *


def check_config(args):
    mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit2, mask_sel0, mask_sel1, mask_sel2, addr_list = args
    hash_machine = NIUOCMHashOpt(mask_0, mask_1, mask_2, sel_bit0, sel_bit1, sel_bit2, mask_sel0, mask_sel1, mask_sel2, getattr(Config, f"hash_gran_{mode}_index"))
    checker = HashChecker(generator.start)
    
    res_all_list = [0 for _ in range(3)]
    
    for addr_list_elem in addr_list:
        res_bin_list = [0 for _ in range(3)]
        for elem in addr_list_elem:
            tgt_id = hash_machine.hash_and(elem)
            res_bin_list[tgt_id] += 1
            res_all_list[tgt_id] += 1
            checker.add_addr(elem, tgt_id, None)
            
        if sum(1 for x in res_bin_list if x != 0) == 1:
            pass 
        else:
            print(hash_machine.get_config())
            raise Exception('error 1')
            return "None"
    
    # print(res_all_list)
    if len(set(res_all_list)) == 1:
        return hash_machine.get_config()
    raise Exception('error 2') 
    return hash_machine.get_mask_config()


if __name__ == '__main__':
    generator = ADDRGenerator(Config.start_address, Config.end_address, getattr(Config, f"hash_gran_{mode}"))
    addr_list = generator.get_gran_addr_list()
    
    with open(f'output/output_{mode}_real.txt', 'r', encoding='utf-8') as f:
        for line in f:
            lst = eval(line.strip()) 
            task_args = (*lst, addr_list)
    
            mask_list = []
            result = check_config(task_args)
            if result is not None:
                mask_list.append(result)
    
    # with open(f'single/output_{mode}_real.txt', 'w', encoding='utf-8') as f:
    #     for item in mask_list:
    #         f.write(str(item) + '\n')