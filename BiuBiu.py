import r2pipe, pefile, os, random, sys
r2 = r2pipe.open(sys.argv[1])
r2.cmd('aaafl')

def lookup_block(block_arr, addr: int):
    for each_block in block_arr:
        if each_block['offset'] == addr:
            return each_block
    return None

graph = r2.cmdj('agj')
graph = graph[0]
def rand_walk(entry_addr, block_arr):
    emu_asm_log = ''
    active_block = lookup_block(block_arr, entry_addr)
    while True:
        curr_block_asm = '\n'.join([each_op['disasm'] for each_op in active_block['ops']])
        emu_asm_log += '\n' + curr_block_asm
        if 'fail' in active_block:
            active_block = lookup_block(block_arr, random.choice([active_block['jump'], active_block['fail']]))
        elif 'jump' in active_block:
            active_block = lookup_block(block_arr, active_block['jump'])
        else:
            print('we done.')
            break
    return emu_asm_log

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
    for c in range(5):
        asm = rand_walk(graph['offset'], graph['blocks'])
        print(f'''
 ---------[ random walking #{c+1} ]---------
 {asm}''')
