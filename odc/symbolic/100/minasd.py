import angr
import claripy
import string

project = angr.Project("./challenge", auto_load_libs= False)

check_addr = project.loader.find_symbol("check").rebased_addr
initial_state = project.factory.blank_state(addr=check_addr, add_options={angr.options.LAZY_SOLVES})
#setting registers
initial_state.regs.rsp = 0x600000
#setting memory
values_addr = project.loader.find_symbol("values").rebased_addr
values = []
for i in range(30):
    var = claripy.BVS(f"var_{i}", 8*8)
    initial_state.solver.add(var >= 0)
    initial_state.solver.add(var <= 61)
    bytes_little_endian = [var.get_byte(j) for j in reversed(range(8))]
    values += bytes_little_endian
symbolic_bv = claripy.Concat(*values)
initial_state.memory.store(values_addr,symbolic_bv)
initial_state.globals["symbolic_bv"] = symbolic_bv
for i in range(30*8):
    print(initial_state.memory.load(values_addr+i, 1))

simulation = project.factory.simgr(initial_state)
simulation.explore(find=[0x400000+0x21C5], avoid=[0x400000+0x21CC])
if simulation.found:
    found = simulation.found[0]
    solution = found.solver.eval(found.globals["symbolic_bv"], cast_to=bytes)
    sol = ""
    symbols = string.digits + string.ascii_letters
    for i in range(0, 30*8, 8):
        sol += symbols[solution[i]]
    print(sol)

