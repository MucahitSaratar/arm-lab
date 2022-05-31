from keystone import *
from unicorn import *
from unicorn.arm64_const import *


class Emulate():
    def __init__(self,base=0x1000000,sta=0x1001000,MB=6,dm=False):
        self.dF = dm
        self.baseAddress = base
        self.stackAddress = sta
        self.mb = 1024*1024 * MB

    def setupEngines(self):
        ### Setup engines for arm
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)


    def compile(self,filename):
        ### setup shellcode
        myasm = open(filename).read()
        asm_tuple = self.ks.asm(myasm)
        self.asm_code = b"".join(x.to_bytes(1,'big') for x in asm_tuple[0])






    ### Functions 

    def hook_mem_invalid(self,uc, access, address, size, value, user_data):
        print(">>> Missing memory is being WRITE at 0x%x, data size = %u, data value = 0x%x, eip = 0x%x"%(address, size, value, uc.reg_read(UC_X86_REG_EIP)))
        return False


    def hook_code(self,uc, address, size, user_data):
        print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))


    def verborse(self,msg):
        if self.dF:
            print(f"[DEBUG] -> {msg}")




    


    def info(self):
        ### Get İnfo if debug setted
        self.verborse(f"Compiled shellcode : {self.asm_code}")





    def setupMemory(self):
    ### Setup memory

        self.mu.mem_map(self.baseAddress, self.mb)
        self.mu.mem_write(self.baseAddress, self.asm_code)
        self.mu.reg_write(UC_ARM64_REG_SP, self.stackAddress)
        self.mu.hook_add(UC_HOOK_MEM_INVALID | UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, self.hook_mem_invalid)
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)

    def setupForEmulate(self,nenereye):
        ### init for emulation
        for i in nenereye:
            self.verborse(f"Register setted to {i[1]}")
            self.mu.reg_write(i[0],0x20)
            #self.mu.reg_write(UC_ARM64_REG_X0,0x21)

    def trig(self):
        print("starting emulation...")
        try:
            self.mu.emu_start(self.baseAddress, self.baseAddress + len(self.asm_code))
        except UcError as e:
            print("ERROR: %s" % e)
            exit()
    
    def run(self,file,setREG=[]):
        self.setupEngines()
        self.compile(filename=file)
        self.info()
        self.setupMemory()
        self.setupForEmulate(setREG)
        self.trig()
        self.verborse("Done")
