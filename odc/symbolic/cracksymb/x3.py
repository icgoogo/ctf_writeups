from z3 import *

a1 = [BitVec(f"c_{i}", 8) for i in range(0x17)]

solver = Solver()

for i in range(0x17):
    solver.add(a1[i] >= 0x20, a1[i] <= 0x7E)

solver.add(
         46 * a1[18]
     + -118 * a1[10]
     + 219 * a1[4]
     + -156 * a1[9]
     + 70 * a1[5]
     + 56 * a1[20]
     + 116 * a1[3]
     + -108 * a1[21]
     + -119 * a1[17]
     + -83 * a1[13]
     + -152 * a1[19]
     + -76 * a1[22]
     + 188 * a1[0]
     + -81 * a1[15]
     + 98 * a1[11]
     + -215 * a1[14]
     + -215 * a1[6]
     + -35 * a1[12]
     - 72 * a1[8]
     - 132 * a1[7]
     + 10 * a1[1]
     + 103 * a1[2]
     + 54203 == 156 * a1[16]
        )
check = solver.check()
print(check)

for i in range(0x17):
    print(chr(solver.model()[a1[i]].as_long()), end="")


