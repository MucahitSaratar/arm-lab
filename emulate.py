from keystone import *
from unicorn import *
from unicorn.arm64_const import *
import argparse

### parsing arguments
aparser = argparse.ArgumentParser(description="Arm opcode executor. (Support only arm64)")
aparser.add_argument("--file","-f",default="arm64.asm",help="Name name for assembly file")
aparser.add_argument("--debug","-d",default=False,help="for verborse set flag to True")
arg = vars(aparser.parse_args())

dosya = arg["file"]
dF = arg["debug"]


### Setup engines




## for arm
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)







### setup shellcode
myasm = open(dosya).read()
asm_tuple = ks.asm(myasm)
asm_code = b"".join(x.to_bytes(1,'big') for x in asm_tuple[0])






### Functions 

def hook_mem_invalid(uc, access, address, size, value, user_data):
    print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x, eip = 0x%x"%(address, size, value, uc.reg_read(UC_X86_REG_EIP)))
    return False


def hook_code(uc, address, size, user_data):
    print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


def verborse(msg):
    if dF:
        print(f"[DEBUG] -> {msg}")




baseAddress = 0x1000000
stackAddress = 0x1001000



### Get İnfo if debug setted
verborse(f"Compiled shellcode : {str(asm_code)}")





### Setup memory

mu.mem_map(baseAddress, 1024*1024*6)
mu.mem_write(baseAddress, asm_code)
mu.reg_write(UC_ARM64_REG_SP, stackAddress)
mu.hook_add(UC_HOOK_MEM_INVALID | UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, hook_mem_invalid)
mu.hook_add(UC_HOOK_CODE, hook_code)

### init for emulation
mu.reg_write(UC_ARM64_REG_X0,0x21)

print("starting emulation...")
try:
    mu.emu_start(baseAddress, baseAddress + len(asm_code))
except UcError as e:
    print("ERROR: %s" % e)
    exit()