from keystone import *
from unicorn import *
from unicorn.arm64_const import *
import utils as U
import argparse

### parsing arguments
aparser = argparse.ArgumentParser(description="Arm opcode executor. (Support only arm64)")
aparser.add_argument("--file","-f",default="arm64.asm",help="Name name for assembly file")
aparser.add_argument("--debug","-d",default=False,help="for verborse set flag to True")
arg = vars(aparser.parse_args())

dosya = arg["file"]
dF = arg["debug"]


core = U.Emulate(dm = dF)
core.run(dosya)