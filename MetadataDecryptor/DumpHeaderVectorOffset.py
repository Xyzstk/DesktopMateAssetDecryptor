import idautils

def get_caller_saved_registers():
    return [0, 1, 2, 8, 9, 10, 11]

def get_modified_registers(insn):
    # Using a set to automatically handle duplicates
    modified_regs = set()

    feature = insn.get_canon_feature()

    # 1. Extract explicitly modified registers
    chg_flags = [
        ida_idp.CF_CHG1, ida_idp.CF_CHG2, ida_idp.CF_CHG3,
        ida_idp.CF_CHG4, ida_idp.CF_CHG5, ida_idp.CF_CHG6,
    ]

    for i, op in enumerate(insn.ops):
        if op.type == ida_ua.o_void:
            break
        
        if (feature & chg_flags[i]) != 0:
            if op.type == ida_ua.o_reg:
                modified_regs.add(op.reg)
                    
    # 2. Add special handler for CALL instructions
    if (feature & ida_idp.CF_CALL) != 0:
        caller_saved = get_caller_saved_registers()
        modified_regs.update(caller_saved)
        
    return list(modified_regs)

res = {}
regNames = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
for xref in idautils.XrefsTo(ida_name.get_name_ea(0, "MetadataHeader")):
    if xref.type == 3:
        ea = xref.frm
        insn = ida_ua.insn_t()
        ea += ida_ua.decode_insn(insn, ea)
        pHeaderReg = insn.Op1.reg
        regEntry = {}
        regOff = [0] * 16
        HeaderRegAvail = True
        flag = False
        for cnt in range(0, 50):
            op1_str = idc.print_operand(ea, 0)
            op2_str = idc.print_operand(ea, 1)
            ea += ida_ua.decode_insn(insn, ea)
            if (insn.Op1.type == idc.o_reg and insn.Op1.reg >= 16) or (insn.Op2.type == idc.o_reg and insn.Op2.reg >= 16):
                continue
            if 'mov' in insn.get_canon_mnem() and insn.Op2.type == idc.o_displ and insn.Op2.reg == pHeaderReg and HeaderRegAvail:
                regEntry[insn.Op1.reg] = insn.Op2.addr
                if insn.Op1.reg == pHeaderReg:
                    HeaderRegAvail = False
                continue
            if insn.itype == ida_allins.NN_retn:
                break
            if insn.Op1.type == idc.o_displ:
                for reg in regEntry.keys():
                    if op1_str.find(regNames[reg]) == op1_str.find("[") + 1:
                        print(f"1-EA: {ea:X}, entry: {regEntry[reg]:X}, value: {(regOff[reg] + insn.Op1.addr):X}")
                        res[regEntry.pop(reg)] = regOff[reg] + insn.Op1.addr
                        flag = True
                        break
            if insn.Op2.type == idc.o_displ:
                for reg in regEntry.keys():
                    if op2_str.find(regNames[reg]) == op2_str.find("[") + 1:
                        print(f"2-EA: {ea:X}, entry: {regEntry[reg]:X}, value: {(regOff[reg] + insn.Op2.addr):X}")
                        res[regEntry.pop(reg)] = regOff[reg] + insn.Op2.addr
                        flag = True
                        break
                if insn.itype == ida_allins.NN_lea:
                    regOff[insn.Op1.reg] += insn.Op2.addr
                    continue
            if insn.Op1.type == idc.o_reg:
                if insn.itype == ida_allins.NN_add:
                    if insn.Op2.type == idc.o_imm:
                        if insn.Op1.reg in regEntry:
                            print(f"3-EA: {ea:X}, entry: {regEntry[insn.Op1.reg]:X}, value: {insn.Op2.value:X}")
                            res[regEntry.pop(insn.Op1.reg)] = insn.Op2.value
                            flag = True
                        else:
                            regOff[insn.Op1.reg] += insn.Op2.value
                    elif insn.Op2.type == idc.o_reg and insn.Op2.reg in regEntry:
                        if regOff[insn.Op1.reg] != 0:
                            print(f"4-EA: {ea:X}, entry: {regEntry[insn.Op2.reg]:X}, value: {regOff[insn.Op1.reg]:X}")
                            res[regEntry.pop(insn.Op2.reg)] = regOff[insn.Op1.reg]
                            flag = True
                        else:
                            regEntry[insn.Op1.reg] = regEntry[insn.Op2.reg]
                            regOff[insn.Op1.reg] = regOff[insn.Op2.reg]
                    continue
                elif insn.itype == ida_allins.NN_sub and insn.Op2.type == idc.o_imm:
                    if insn.Op1.reg in regEntry:
                        print(f"5-EA: {ea:X}, entry: {regEntry[insn.Op1.reg]:X}, value: {-insn.Op2.value:X}")
                        res[regEntry.pop(insn.Op1.reg)] = -insn.Op2.value
                        flag = True
                    else:
                        regOff[insn.Op1.reg] -= insn.Op2.value
                    continue
                elif insn.itype == ida_allins.NN_mov and insn.Op2.type == idc.o_reg and insn.Op1.reg != insn.Op2.reg:
                    regOff[insn.Op1.reg] = regOff[insn.Op2.reg]
                    if insn.Op2.reg in regEntry:
                        regEntry[insn.Op1.reg] = regEntry[insn.Op2.reg]
                    continue
            for reg in get_modified_registers(insn):
                if reg == pHeaderReg:
                    HeaderRegAvail = False
                regOff[reg] = 0
                if reg in regEntry:
                    regEntry.pop(reg)
        if flag == False:
            print(f"Failed at {xref.frm:X}")
for k, v in res.items():
    if (v >> 63) == 1:
        v = -(0x10000000000000000 - v)
    if v < 0:
        print(f"(0x{k:X}, -0x{-v:X}),")
    else:
        print(f"(0x{k:X}, 0x{v:X}),")
print(len(res))
