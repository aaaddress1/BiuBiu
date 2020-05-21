import r2pipe, pefile, os, random, sys
r2 = r2pipe.open(sys.argv[1])
r2.cmd('aaafl')
entry_addr = r2.cmdj('agj')[0]['offset']

def lookup_block(addr: int):
    for each_block in r2.cmdj(f'agj {hex(addr)}')[0]['blocks']:
        if each_block['offset'] == addr:
            return each_block
    return None

def rand_walk(entry_addr):
    emu_asm_log = ''
    sub_label = []
    active_block = lookup_block(entry_addr)
    while True:
        for each_op in active_block['ops']:
            emu_asm_log += f"{each_op['offset']}\t:\t{each_op['disasm']}" + '\n'
            if each_op['type'] == 'call': sub_label.append(each_op['jump'])
        if 'fail' in active_block:
            active_block = lookup_block(random.choice([active_block['jump'], active_block['fail']]))
        elif 'jump' in active_block:
            active_block = lookup_block(active_block['jump'])
        else:
            break
    return emu_asm_log, sub_label

if __name__ == "__main__":
    print('''
██████╗ ██╗██╗   ██╗██████╗ ██╗██╗   ██╗
██╔══██╗██║██║   ██║██╔══██╗██║██║   ██║
██████╔╝██║██║   ██║██████╔╝██║██║   ██║
██╔══██╗██║██║   ██║██╔══██╗██║██║   ██║
██████╔╝██║╚██████╔╝██████╔╝██║╚██████╝
> BiuBiu: Tool for Random-Walking, based on radare2.
                    / v1.1 by aaaddress1@chroot.org
''')
    label_record = {}
    asm, sub_label = rand_walk(entry_addr)
    label_record[entry_addr] = asm
    while True:
        found_uncoverd_label = any(l not in label_record for l in sub_label)
        for each_label in sub_label:
            if each_label not in label_record:
                asm, sub2_label = rand_walk(each_label)
                sub_label += sub2_label
                label_record[each_label] = asm
        if found_uncoverd_label == False:
            break
    while True:
        print('--------- [ func blocks ] ---------')
        for indx, func_addr in enumerate(label_record):
            print(f'\t#{indx} -> {hex(func_addr)}... instruction count = {len(label_record[func_addr].splitlines())}')

        indx = int(input('which one you want to go around? (number): '))
        choosen_addr = [l for l in label_record][indx]
        print(f"great! let's get random-walking at sub_{hex(choosen_addr)}")
        print(label_record[choosen_addr])