
class Option:
    hash_2K = ['2K', '4K']
    hash_1K = ['1K', '2K']
    hash_512 = ['512', '1K']
    hash_256 = ['256', '512']

for hash_key in ['2K', '1K', '512', '256']:
    new_lines = []
    config = getattr(Option, f"hash_{hash_key}")
    
    with open(f'output/output_{config[1]}_real.txt', 'r', encoding='utf-8') as f_high:
        high_lines = set(f_high.readlines())

    with open(f'output/output_{config[0]}_real.txt', 'r', encoding='utf-8') as f_low:
        for line in f_low:
            if line not in high_lines:
                new_lines.append(line)

    with open(f'output/output_{hash_key}_final.txt', 'w', encoding='utf-8') as f_out:
        f_out.writelines(new_lines)

         