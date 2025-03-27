#ifndef LIBDECOMP_BACKEND_CAPSTONE_H
#define LIBDECOMP_BACKEND_CAPSTONE_H

#include "../backend.h"
#include "../libdecomp.h"
#include <assert.h>
#include <capstone/capstone.h>
#include <stdio.h>

typedef struct DCCapstoneData {
    int arch, mode;
} DCCapstoneData;

static inline cs_arch get_arch(DCDisassemblerBackend *self)
{
    return ((DCCapstoneData*)self->backend_dependent_data)->arch;
}

static bool dc_cs_instruction_is_jump(DCDisassemblerBackend *self, void *iobj)
{
    cs_insn *ins = iobj;
    
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return (ins->id >= X86_INS_JAE && ins->id <= X86_INS_JS) || ins->id == X86_INS_JMP;
    case CS_ARCH_ARM64:
        return ins->id == ARM64_INS_B;
    default:
        return false;
    }
}

static bool dc_cs_instruction_is_jcc(DCDisassemblerBackend *self, void *iobj)
{
    cs_insn *ins = iobj;

    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ins->id != X86_INS_JMP;
    case CS_ARCH_ARM64:
        return ins->id == ARM64_INS_B && (ins->detail->arm64.cc != ARM64_CC_AL && ins->detail->arm64.cc != ARM64_CC_NV && ins->detail->arm64.cc != 0);
    default:
        return false;
    }
}

static uint64_t dc_cs_instruction_get_jump_target(DCDisassemblerBackend *self, void *iobj)
{
    cs_insn *ins = iobj;
    
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ins->detail->x86.operands[0].imm;
    case CS_ARCH_ARM64:
        return ins->detail->arm64.operands[0].imm;
    default:
        return 0;
    }
}

static uint64_t dc_cs_instruction_get_jump_passed(DCDisassemblerBackend *self, void *iobj)
{
    cs_insn *ins = iobj;
    return ins->address + ins->size;
}

static uint64_t dc_cs_instruction_get_address(DCDisassemblerBackend *self, void *iobj)
{
    cs_insn *ins = iobj;
    return ins->address;
}

static void *dc_cs_instruction_get_operand(DCDisassemblerBackend *self, void *iobj, int index)
{
    cs_insn *ins = iobj;

    switch (get_arch(self)) {
    case CS_ARCH_X86:
        if (index < 0 || index >= ins->detail->x86.op_count) return NULL;
        return &ins->detail->x86.operands[index];
    case CS_ARCH_ARM64:
        if (index < 0 || index >= ins->detail->arm64.op_count) return NULL;
        return &ins->detail->arm64.operands[index];
    default:
        return NULL;
    } 
}

static DCDisassemblerOperandType dc_cs_operand_get_type(DCDisassemblerBackend *self, void *oobj)
{
#define GENERIC_SWITCH(typed, op_imm, op_reg, op_mem) \
    do { \
        switch (((typed*)oobj)->type) { \
        case op_imm: return DC_DISASM_OPERAND_IMM; \
        case op_reg: return DC_DISASM_OPERAND_REG; \
        case op_mem: return DC_DISASM_OPERAND_MEM; \
        default: return DC_DISASM_OPERAND_INVALID; \
        } \
    } while (0);

    switch (get_arch(self)) {
    case CS_ARCH_X86:
        GENERIC_SWITCH(cs_x86_op, X86_OP_IMM, X86_OP_REG, X86_OP_MEM);
    case CS_ARCH_ARM64:
        GENERIC_SWITCH(cs_arm64_op, ARM64_OP_IMM, ARM64_OP_REG, ARM64_OP_MEM);
    default:
        return DC_DISASM_OPERAND_INVALID;
    } 

#undef GENERIC_SWITCH
}

static size_t dc_cs_operand_get_bitsize(DCDisassemblerBackend *self, void *oobj)
{
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->size * 8;
    case CS_ARCH_ARM64:
        if (self->operand_get_type(self, oobj) == DC_DISASM_OPERAND_REG) {
            int reg = ((cs_arm64_op*)oobj)->reg;
            if ((reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28) || reg == ARM64_REG_SP)
                return 64;
            if (reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30)
                return 32;
            if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31)
                return 16;
            if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31)
                return 8;
            return 64;
        }
        return 32;
    default:
        return 0;
    }
}

static int dc_cs_operand_register_index(DCDisassemblerBackend *self, void *oobj)
{
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->reg;
    case CS_ARCH_ARM64:
        return ((cs_arm64_op*)oobj)->reg;
    default:
        return 0;
    }
}

static int dc_cs_operand_register_largest_enclosing_index(DCDisassemblerBackend *self, int index)
{
    static const int table_x86_64[] = { 0,
        X86_REG_RAX, X86_REG_RAX, X86_REG_RAX, X86_REG_RBX, X86_REG_RBX,
        X86_REG_RBP, X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RCX,
        X86_REG_CS, X86_REG_RCX, X86_REG_RDX, X86_REG_RDI, X86_REG_RDI,
        X86_REG_RDX, X86_REG_DS, X86_REG_RDX, X86_REG_RAX, X86_REG_RBP,
        X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX, X86_REG_EFLAGS,
        X86_REG_RIP, X86_REG_RIZ, X86_REG_ES, X86_REG_RSI, X86_REG_RSP,
        X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_RIP, X86_REG_RAX,
        X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX,
        X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_RSI,
        X86_REG_RSI, X86_REG_RSP, X86_REG_RSP, X86_REG_SS,
    };

    static const int table_x86_32[] = { 0,
        X86_REG_EAX, X86_REG_EAX, X86_REG_EAX, X86_REG_EBX, X86_REG_EBX,
        X86_REG_EBP, X86_REG_EBP, X86_REG_EBX, X86_REG_ECX, X86_REG_ECX,
        X86_REG_CS, X86_REG_ECX, X86_REG_EDX, X86_REG_EDI, X86_REG_EDI,
        X86_REG_EDX, X86_REG_DS, X86_REG_EDX, X86_REG_EAX, X86_REG_EBP,
        X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX, X86_REG_EFLAGS,
        X86_REG_EIP, X86_REG_EIZ, X86_REG_ES, X86_REG_ESI, X86_REG_ESP,
        X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_EIP, X86_REG_EAX,
        X86_REG_EBP, X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX,
        X86_REG_EIP, X86_REG_EIZ, X86_REG_ESI, X86_REG_ESP, X86_REG_ESI,
        X86_REG_ESI, X86_REG_ESP, X86_REG_ESP, X86_REG_SS,
    };

    static const int table_x86_16[] = { 0,
        X86_REG_AX, X86_REG_AX, X86_REG_AX, X86_REG_BX, X86_REG_BX,
        X86_REG_BP, X86_REG_BP, X86_REG_BX, X86_REG_CX, X86_REG_CX,
        X86_REG_CS, X86_REG_CX, X86_REG_DX, X86_REG_DI, X86_REG_DI,
        X86_REG_DX, X86_REG_DS, X86_REG_DX, X86_REG_AX, X86_REG_BP,
        X86_REG_BX, X86_REG_CX, X86_REG_DI, X86_REG_DX, X86_REG_EFLAGS,
        X86_REG_IP, X86_REG_EIZ, X86_REG_ES, X86_REG_SI, X86_REG_SP,
        X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_IP, X86_REG_AX,
        X86_REG_BP, X86_REG_BX, X86_REG_CX, X86_REG_DI, X86_REG_DX,
        X86_REG_IP, X86_REG_EIZ, X86_REG_SI, X86_REG_SP, X86_REG_SI,
        X86_REG_SI, X86_REG_SP, X86_REG_SP, X86_REG_SS,
    };

    static const size_t max = sizeof(table_x86_64) / sizeof(*table_x86_64);
    if (index < 0 || index >= max) 
        return -1;

    switch (((DCCapstoneData*)self->backend_dependent_data)->mode) {
    case CS_MODE_64: return table_x86_64[index];
    case CS_MODE_32: return table_x86_32[index];
    case CS_MODE_16: return table_x86_16[index];
    default: return -1;
    }
}

static int dc_cs_operand_memory_base_register_index(DCDisassemblerBackend *self, void *oobj)
{
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->mem.base;
    case CS_ARCH_ARM64:
        return ((cs_arm64_op*)oobj)->mem.base;
    default:
        return 0;
    }
}

static int64_t dc_cs_operand_memory_disp(DCDisassemblerBackend *self, void *oobj)
{
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->mem.disp;
    case CS_ARCH_ARM64:
        return ((cs_arm64_op*)oobj)->mem.disp;
    default:
        return 0;
    }
}

static bool dc_cs_operand_is_stack_var(DCDisassemblerBackend *self, void *oobj)
{
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->mem.base == X86_REG_RBP;
    case CS_ARCH_ARM64:
        return ((cs_arm64_op*)oobj)->mem.base == ARM64_REG_SP;
    default:
        return false;
    }
}

static bool dc_cs_operand_is_ret_val(DCDisassemblerBackend *self, void *oobj)
{
    if (self->operand_get_type(self, oobj) != DC_DISASM_OPERAND_REG)
        return false;

    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->reg == X86_REG_RAX || ((cs_x86_op*)oobj)->reg == X86_REG_EAX || ((cs_x86_op*)oobj)->reg == X86_REG_AX;
    case CS_ARCH_ARM64:
        return ((cs_arm64_op*)oobj)->reg == ARM64_REG_X0 || ((cs_arm64_op*)oobj)->reg == ARM64_REG_W0;
    default:
        return false;
    }
}

static uint64_t dc_cs_operand_immediate_value(DCDisassemblerBackend *self, void *oobj)
{
    switch (get_arch(self)) {
    case CS_ARCH_X86:
        return ((cs_x86_op*)oobj)->imm;
    case CS_ARCH_ARM64:
        return ((cs_arm64_op*)oobj)->imm;
    default:
        return 0;
    }
}

static bool dc_cs_operand_cmp(DCDisassemblerBackend *self, void *oobj0, void *oobj1) 
{
    if (!oobj0 || !oobj1) 
        return false;

    if (get_arch(self) == CS_ARCH_X86) {
        cs_x86_op *op1 = oobj0;
        cs_x86_op *op2 = oobj1;

        if (op1->type != op2->type) 
            return false;
        
        switch (op1->type) {
        case X86_OP_REG:
            return op1->reg == op2->reg;
        case X86_OP_MEM:
            return (
                   op1->mem.segment == op2->mem.segment &&
                   op1->mem.base == op2->mem.base &&
                   op1->mem.index == op2->mem.index &&
                   op1->mem.scale == op2->mem.scale &&
                   op1->mem.disp == op2->mem.disp);
        default:
            return false;
        }
    }
    else if (get_arch(self) == CS_ARCH_ARM64) {
        cs_arm64_op *op1 = oobj0;
        cs_arm64_op *op2 = oobj1;

        if (op1->type != op2->type) 
            return false;
        
        switch (op1->type) {
        case X86_OP_REG:
            return op1->reg == op2->reg;
        case X86_OP_MEM:
            return (
                   op1->mem.base == op2->mem.base &&
                   op1->mem.index == op2->mem.index &&
                   op1->mem.disp == op2->mem.disp);
        default:
            return false;
        }
    }

    return false;
}

static inline DCLangOpcodeEnum dc_cs_to_il_opcode(DCDisassemblerBackend *self, int mnemonic, cs_insn *ins)
{
    if (get_arch(self) == CS_ARCH_X86) {
        switch (mnemonic) {
        case X86_INS_ADD: return DC_IL_ADD;
        case X86_INS_SUB: return DC_IL_SUB;
        case X86_INS_AND: return DC_IL_AND;
        case X86_INS_OR: return DC_IL_OR;
        case X86_INS_XOR: return DC_IL_XOR;
        case X86_INS_SHL: return DC_IL_SHL;
        case X86_INS_SHR: return DC_IL_SHR;
        case X86_INS_JE: return DC_IL_JZ;
        case X86_INS_JNE: return DC_IL_JNZ;
        case X86_INS_JB: return DC_IL_JB;
        case X86_INS_JAE: return DC_IL_JNB;
        case X86_INS_JBE: return DC_IL_JBE;
        case X86_INS_JA: return DC_IL_JNBE;
        case X86_INS_JL: return DC_IL_JL;
        case X86_INS_JLE: return DC_IL_JLE;
        case X86_INS_JGE: return DC_IL_JNL;
        case X86_INS_JG: return DC_IL_JNLE;
        case X86_INS_JNS: return DC_IL_JNS;
        case X86_INS_JS: return DC_IL_JS;
        default: return DC_IL_INVALID;
        }
    }
    else if (get_arch(self) == CS_ARCH_ARM64) {
        switch (mnemonic) {
        case ARM64_INS_ADD: return DC_IL_ADD;
        case ARM64_INS_SUB: return DC_IL_SUB;
        case ARM64_INS_AND: return DC_IL_AND;
        case ARM64_INS_ORR: return DC_IL_OR;
        case ARM64_INS_EOR: return DC_IL_XOR;
        case ARM64_INS_LSL: return DC_IL_SHL;
        case ARM64_INS_LSR: return DC_IL_SHR;
        case ARM64_INS_B: {
            switch (ins->detail->arm64.cc) {
            case ARM64_CC_EQ: return DC_IL_JZ;
            case ARM64_CC_NE: return DC_IL_JNZ;
            case ARM64_CC_MI: return DC_IL_JS;
            case ARM64_CC_PL: return DC_IL_JNS;
            case ARM64_CC_LO: return DC_IL_JB;
            case ARM64_CC_HS: return DC_IL_JNB;
            case ARM64_CC_HI: return DC_IL_JNBE;
            case ARM64_CC_LS: return DC_IL_JBE;
            case ARM64_CC_LT: return DC_IL_JL;
            case ARM64_CC_GE: return DC_IL_JNL;
            case ARM64_CC_GT: return DC_IL_JNLE;
            case ARM64_CC_LE: return DC_IL_JLE;
            case ARM64_CC_AL:
            case ARM64_CC_NV:
            case 0:           return DC_IL_JMP;
            case ARM64_CC_VS:
            case ARM64_CC_VC:
            default: return DC_IL_INVALID;
            }
        }
        default: return DC_IL_INVALID;
        }
    }

    return DC_IL_INVALID;
}

static void dc_cs_lift_instruction(DCDisassemblerBackend *self, void *iobj, void *il_routinev, void *il_basic_block)
{
    DCDisassemblerBackend backend = *self;
    cs_insn *ins = iobj;
    DCLangBasicBlock *il_bb = il_basic_block;
    DCLangRoutine *il_routine = il_routinev;

    if (get_arch(self) == CS_ARCH_X86) {
        switch (ins->id) {
        case X86_INS_MOV:
        case X86_INS_LEA:
            if (ins->detail->x86.operands[0].reg == X86_REG_RBP && ins->detail->x86.operands[1].reg == X86_REG_RSP)
                break;
            il_load(backend, il_routine, il_bb, &ins->detail->x86.operands[1]);
            il_store(backend, il_routine, il_bb, &ins->detail->x86.operands[0]);
            break;
        case X86_INS_ADD:
        case X86_INS_SUB:
        case X86_INS_SHL:
            il_load(backend, il_routine, il_bb, &ins->detail->x86.operands[0]);
            il_load(backend, il_routine, il_bb, &ins->detail->x86.operands[1]);
            add_ins(&il_bb->instructions, (DCLangInstruction){
                    .opcode = dc_cs_to_il_opcode(self, ins->id, ins), .size = ins->detail->x86.operands[0].size });
            il_store(backend, il_routine, il_bb, &ins->detail->x86.operands[0]);
            break;
        case X86_INS_CMP:
            il_load(backend, il_routine, il_bb, &ins->detail->x86.operands[1]);
            il_load(backend, il_routine, il_bb, &ins->detail->x86.operands[0]);
            add_ins(&il_bb->instructions, (DCLangInstruction){
                    .opcode = DC_IL_CMP, .size = ins->detail->x86.operands[0].size });
            break;
        case X86_INS_NEG:
            il_load(backend, il_routine, il_bb, &ins->detail->x86.operands[0]);
            add_ins(&il_bb->instructions, (DCLangInstruction){
                    .opcode = DC_IL_NEG, .size = ins->detail->x86.operands[0].size });
            il_store(backend, il_routine, il_bb, &ins->detail->x86.operands[0]);
            break;
        case X86_INS_JE:
        case X86_INS_JNE:
        case X86_INS_JB:
        case X86_INS_JAE:
        case X86_INS_JBE:
        case X86_INS_JA:
        case X86_INS_JL:
        case X86_INS_JLE:
        case X86_INS_JGE:
        case X86_INS_JG:
        case X86_INS_JNS:
        case X86_INS_JS:
            il_bb->go_to_true = (void*)self->instruction_get_jump_target(self, ins);
            il_bb->go_to = (void*)self->instruction_get_jump_passed(self, ins);
            add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = dc_cs_to_il_opcode(self, ins->id, ins) });
            break;
        case X86_INS_JMP:
            il_bb->go_to = (void*)self->instruction_get_jump_target(self, ins);
            add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_JMP });
            break;
        case X86_INS_RET:
            {
                for (DCLangVariable *v = il_routine->variables; v; v = v->next)
                    if (self->operand_is_ret_val(self, v->native_operand)) {
                        il_load(backend, il_routine, il_bb, v->native_operand);
                        add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_RET });
                    }
            }
            break;
        default:
            break;
        }
    } 
    else if (get_arch(self) == CS_ARCH_ARM64) {
        switch (ins->id) {
        case ARM64_INS_MOV:
        case ARM64_INS_LDR:
            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[1]);
            il_store(backend, il_routine, il_bb, &ins->detail->arm64.operands[0]);
            break;
        case ARM64_INS_STR:
            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[0]);
            il_store(backend, il_routine, il_bb, &ins->detail->arm64.operands[1]);
            break;
        case ARM64_INS_ADD:
        case ARM64_INS_SUB:
        case ARM64_INS_SHL:
            /*
             * ignore stack setup, we should probably save this somewhere? (to-do)
             */
            if (self->operand_get_type(self, &ins->detail->arm64.operands[0]) == DC_DISASM_OPERAND_REG
                && self->operand_get_type(self, &ins->detail->arm64.operands[1]) == DC_DISASM_OPERAND_REG
                && ins->detail->arm64.operands[0].reg == ARM64_REG_SP
                && ins->detail->arm64.operands[1].reg == ARM64_REG_SP)
                    break;

            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[1]);
            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[2]);
            add_ins(&il_bb->instructions, (DCLangInstruction){
                    .opcode = dc_cs_to_il_opcode(self, ins->id, ins), .size = 64 });
            il_store(backend, il_routine, il_bb, &ins->detail->arm64.operands[0]);
            break;
        case ARM64_INS_CMP:
            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[1]);
            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[0]);
            add_ins(&il_bb->instructions, (DCLangInstruction){
                    .opcode = DC_IL_CMP, .size = 32 });
            break;
        case ARM64_INS_NEG:
            il_load(backend, il_routine, il_bb, &ins->detail->arm64.operands[1]);
            add_ins(&il_bb->instructions, (DCLangInstruction){
                    .opcode = DC_IL_NEG, .size = 32 });
            il_store(backend, il_routine, il_bb, &ins->detail->arm64.operands[0]);
            break;
        case ARM64_INS_B:
            if (self->instruction_is_jcc(self, ins)) {
                il_bb->go_to_true = (void*)self->instruction_get_jump_target(self, ins);
                il_bb->go_to = (void*)self->instruction_get_jump_passed(self, ins);
                add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = dc_cs_to_il_opcode(self, ins->id, ins) });
            }
            else {
                il_bb->go_to = (void*)self->instruction_get_jump_target(self, ins);
                add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_JMP });
            }
            break;
        case ARM64_INS_RET:
            {
                for (DCLangVariable *v = il_routine->variables; v; v = v->next)
                    if (self->operand_is_ret_val(self, v->native_operand)) {
                        il_load(backend, il_routine, il_bb, v->native_operand);
                        add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_RET });
                    }
            }
            break;
        default:
            break;
        }
    }
}

static DCDisassemblerBackend DC_DisassemblerCapstone(cs_arch arch, cs_mode mode)
{
    if (arch != CS_ARCH_X86 && arch != CS_ARCH_ARM64)
        assert(false && "bad architecture");
        // return (DCDisassemblerBackend){};
    
    DCCapstoneData *data = malloc(sizeof(DCCapstoneData));
    data->arch = arch;
    data->mode = mode;

    return (DCDisassemblerBackend){
        .backend_dependent_data = data,
        .instruction_is_jump = dc_cs_instruction_is_jump,
        .instruction_is_jcc = dc_cs_instruction_is_jcc,
        .instruction_get_jump_target = dc_cs_instruction_get_jump_target,
        .instruction_get_jump_passed = dc_cs_instruction_get_jump_passed,
        .instruction_get_address = dc_cs_instruction_get_address,
        .instruction_get_operand = dc_cs_instruction_get_operand,
        .operand_get_type = dc_cs_operand_get_type,
        .operand_get_bitsize = dc_cs_operand_get_bitsize,
        .operand_register_index = dc_cs_operand_register_index,
        .operand_register_largest_enclosing_index = dc_cs_operand_register_largest_enclosing_index,
        .operand_memory_base_register_index = dc_cs_operand_memory_base_register_index,
        .operand_memory_disp = dc_cs_operand_memory_disp,
        .operand_is_stack_var = dc_cs_operand_is_stack_var,
        .operand_is_ret_val = dc_cs_operand_is_ret_val,
        .operand_immediate_value = dc_cs_operand_immediate_value,
        .operand_cmp = dc_cs_operand_cmp,
        .lift_instruction = dc_cs_lift_instruction
    };
}

#endif /* LIBDECOMP_BACKEND_CAPSTONE_H */
