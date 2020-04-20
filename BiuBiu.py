# BiBiu, by aaaddress1@chroot.org
from capstone import *
from capstone.x86 import *
import pefile

class block:
    def __init__(self, rip, blockList):
        self.id = len(blockList)
        self.addr = rip # first instruct of block
        self.successor = None # next block
        self.bytecode = b''
        blockList.append(self)
    
    def showAsm(self):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        for (address, size, mnemonic, op_str) \
            in md.disasm_lite(self.bytecode, self.addr):
            print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

class exeBiuBiu:
    def __init__(self, filePath):
        self.blockList = [] # record all basic block
        self.funcEntry = [] # begin of function.
        self.path = filePath
        self.exefile = pefile.PE(self.path)
        self.peImgBase = self.exefile.OPTIONAL_HEADER.ImageBase
        self.epVA = self.exefile.OPTIONAL_HEADER.AddressOfEntryPoint
        self.dynamicImg = self.exefile.get_memory_mapped_image(ImageBase = self.peImgBase)

    def blockWalk(self, rip = 0):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True

        if not any(x.addr == rip for x in self.blockList):
            entry_block = block(rip, self.blockList)
        else:
            entry_block = [x for x in self.blockList if x.addr == rip][0]

        done = False
        active_block = entry_block
        while not done:
            for instruct in md.disasm(self.dynamicImg[active_block.addr - self.peImgBase: ], active_block.addr):
                active_block.bytecode += instruct.bytes
                #print(f'\t -> {hex(instruct.address)} {instruct.mnemonic} {instruct.op_str}')
                
                if X86_GRP_CALL in instruct.groups and instruct.id == X86_INS_CALL: # relative short jump
                    if X86_OP_IMM == instruct.operands[0].type: # assert: [short call] [rva]
                        callee_addr = instruct.operands[0].value.imm
                        if not any(x.addr == callee_addr for x in self.funcEntry):
                            newFunc_block_entry = block(callee_addr, self.blockList)
                            self.funcEntry.append(newFunc_block_entry)
                            #print(f'[+] detect new func entry @ {hex(callee_addr)}')

                if X86_GRP_JUMP in instruct.groups and instruct.id == X86_INS_JMP:  # relative short jump
                    # create new block, and assigned as a successor to the current block.
                    if X86_OP_IMM == instruct.operands[0].type:      # assert: [short jump] [rva]
                        next_rip = instruct.operands[0].value.imm
                        next_block = block(next_rip, self.blockList)
                        active_block.successor = next_block
                        active_block = next_block
                        break
                    elif X86_OP_MEM == instruct.operands[0].type: # assert [long jump] [rva]
                        done = True
                        break # we couldn't handle this kinda long jump, sorry :(
                
                if X86_GRP_RET in instruct.groups:
                    done = True
                    break # we're in the lastest block.
        return entry_block
    
    def walk(self):
        self.funcEntry.append(self.blockWalk(self.peImgBase + self.epVA))
        while any(len(x.bytecode) == 0 for x in self.funcEntry):
            for entryBlock in self.funcEntry:
                if len(entryBlock.bytecode) == 0:
                    self.blockWalk(entryBlock.addr)

    def getFuncSize(self, funcEntryRip):
        curr_block = [x for x in biu.funcEntry if x.addr == biu.peImgBase + biu.epVA][0]
        sumSize = 0
        while True:
            sumSize += len(curr_block.bytecode)
            curr_block = curr_block.successor
            if None == curr_block:
                return sumSize
    
    def displyAsm(self, funcEntryRip):
        curr_block = [x for x in biu.funcEntry if x.addr == biu.peImgBase + biu.epVA][0]
        while True:
            curr_block.showAsm()
            curr_block = curr_block.successor
            if None == curr_block:
                break
        
if __name__ == "__main__":

    print('''
██████╗ ██╗██╗   ██╗██████╗ ██╗██╗   ██╗
██╔══██╗██║██║   ██║██╔══██╗██║██║   ██║
██████╔╝██║██║   ██║██████╔╝██║██║   ██║
██╔══██╗██║██║   ██║██╔══██╗██║██║   ██║
██████╔╝██║╚██████╔╝██████╔╝██║╚██████╔╝
╚═════╝ ╚═╝ ╚═════╝ ╚═════╝ ╚═╝ ╚═════╝ 
> BiuBiu: Control-Flow-Graph Bruteforce
          v1.0 by aaaddress1@chroot.org
''')
    biu = exeBiuBiu(input('choose a exe file: '))
    print(f'[+] get mapped image base @ {hex(biu.peImgBase)}, ep @ {hex(biu.peImgBase + biu.epVA)}')

    # enumerate all function of exe file.
    biu.walk()

    while True:
        print('''
            #1 - enumerate func
            #2 - display assembly code of a func
            #3 - exit
        ''')
        choise = int(input('input a number: '))

        if choise == 1:
            print('[+] enumerate function entry block...')
            for fx in biu.funcEntry:
                print(f'\t-> func @ {hex(fx.addr)}')
        elif choise == 2:
            print('[+] display assembly code of entry function ...')
            biu.displyAsm(int(input('func addr: '), 0))
        elif choise == 3:
            break
