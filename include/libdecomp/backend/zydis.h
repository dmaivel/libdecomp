#ifndef LIBDECOMP_BACKEND_ZYDIS_H
#define LIBDECOMP_BACKEND_ZYDIS_H

#include "../backend.h"
#include "../libdecomp.h"
#include "Zydis/SharedTypes.h"
#include <Zydis/Zydis.h>
#include <stdio.h>

typedef struct DCZydisData {
    int mode;
} DCZydisData;

static bool dc_zy_instruction_is_jump(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->info.mnemonic >= ZYDIS_MNEMONIC_JB && ins->info.mnemonic <= ZYDIS_MNEMONIC_JZ;
}

static bool dc_zy_instruction_is_jcc(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->info.mnemonic != ZYDIS_MNEMONIC_JMP;
}

static bool dc_zy_instruction_is_call(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->info.mnemonic == ZYDIS_MNEMONIC_CALL;
}

static bool dc_zy_instruction_is_ret(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->info.mnemonic == ZYDIS_MNEMONIC_RET;
}

static uint64_t dc_zy_instruction_get_jump_target(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->runtime_address + ins->operands[0].imm.value.s + ins->info.length;
}

static uint64_t dc_zy_instruction_get_jump_passed(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->runtime_address + ins->info.length;
}

static uint64_t dc_zy_instruction_get_address(DCDisassemblerBackend *self, void *iobj)
{
    ZydisDisassembledInstruction *ins = iobj;
    return ins->runtime_address;
}

static void *dc_zy_instruction_get_operand(DCDisassemblerBackend *self, void *iobj, int index)
{
    ZydisDisassembledInstruction *ins = iobj;
    
    if (index < 0 || index >= ins->info.operand_count)
        return NULL;

    return &ins->operands[index];
}

static DCDisassemblerOperandType dc_zy_operand_get_type(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    switch (operand->type) {
    case ZYDIS_OPERAND_TYPE_IMMEDIATE: return DC_DISASM_OPERAND_IMM;
    case ZYDIS_OPERAND_TYPE_REGISTER: return DC_DISASM_OPERAND_REG;
    case ZYDIS_OPERAND_TYPE_MEMORY: return DC_DISASM_OPERAND_MEM;
    default: printf("(%d)\n", operand->type); assert("unknown zydis operand type\n" && false);
    }
}

static size_t dc_zy_operand_get_bitsize(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->size;
}

static int dc_zy_operand_register_index(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->reg.value;
}

static int dc_zy_operand_register_largest_enclosing_index(DCDisassemblerBackend *self, int index)
{
    return ZydisRegisterGetLargestEnclosing(((DCZydisData*)self->backend_dependent_data)->mode, index);
}

static int dc_zy_operand_memory_base_register_index(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->mem.base;
}

static int64_t dc_zy_operand_memory_disp(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->mem.disp.value;
}

static bool dc_zy_operand_is_stack_var(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->mem.base == ZYDIS_REGISTER_RBP;
}

static bool dc_zy_operand_is_ret_val(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->type == ZYDIS_OPERAND_TYPE_REGISTER && ZydisRegisterGetLargestEnclosing(((DCZydisData*)self->backend_dependent_data)->mode, operand->reg.value) == ZYDIS_REGISTER_RAX;
}

static uint64_t dc_zy_operand_immediate_value(DCDisassemblerBackend *self, void *oobj)
{
    ZydisDecodedOperand *operand = oobj;
    return operand->imm.value.u;
}

static bool dc_zy_operand_cmp(DCDisassemblerBackend *self, void *oobj0, void *oobj1) {
    ZydisDecodedOperand *op1 = oobj0;
    ZydisDecodedOperand *op2 = oobj1;

    if (!op1 || !op2) return false;
    if (op1->type != op2->type) return false;
    switch (op1->type) {
    case ZYDIS_OPERAND_TYPE_REGISTER:
        return op1->reg.value == op2->reg.value;
    case ZYDIS_OPERAND_TYPE_MEMORY:
        return (op1->mem.type == op2->mem.type &&
               op1->mem.segment == op2->mem.segment &&
               op1->mem.base == op2->mem.base &&
               op1->mem.index == op2->mem.index &&
               op1->mem.scale == op2->mem.scale &&
               op1->mem.disp.has_displacement == op2->mem.disp.has_displacement &&
               op1->mem.disp.value == op2->mem.disp.value);
    case ZYDIS_OPERAND_TYPE_POINTER:
        return (op1->ptr.segment == op2->ptr.segment &&
               op1->ptr.offset == op2->ptr.offset);
    case ZYDIS_OPERAND_TYPE_IMMEDIATE:
        return (op1->imm.is_signed == op2->imm.is_signed &&
               op1->imm.is_relative == op2->imm.is_relative &&
               op1->imm.value.u == op2->imm.value.u);
    default:
        return false;
    }
}

static inline DCLangOpcodeEnum dc_zy_to_il_opcode(int mnemonic)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_ADD: return DC_IL_ADD;
    case ZYDIS_MNEMONIC_SUB: return DC_IL_SUB;
    case ZYDIS_MNEMONIC_AND: return DC_IL_AND;
    case ZYDIS_MNEMONIC_OR: return DC_IL_OR;
    case ZYDIS_MNEMONIC_XOR: return DC_IL_XOR;
    case ZYDIS_MNEMONIC_SHL: return DC_IL_SHL;
    case ZYDIS_MNEMONIC_SHR: return DC_IL_SHR;
    case ZYDIS_MNEMONIC_JZ: return DC_IL_JZ;
    case ZYDIS_MNEMONIC_JNZ: return DC_IL_JNZ;
    case ZYDIS_MNEMONIC_JB: return DC_IL_JB;
    case ZYDIS_MNEMONIC_JNB: return DC_IL_JNB;
    case ZYDIS_MNEMONIC_JBE: return DC_IL_JBE;
    case ZYDIS_MNEMONIC_JNBE: return DC_IL_JNBE;
    case ZYDIS_MNEMONIC_JL: return DC_IL_JL;
    case ZYDIS_MNEMONIC_JLE: return DC_IL_JLE;
    case ZYDIS_MNEMONIC_JNL: return DC_IL_JNL;
    case ZYDIS_MNEMONIC_JNLE: return DC_IL_JNLE;
    case ZYDIS_MNEMONIC_JNS: return DC_IL_JNS;
    case ZYDIS_MNEMONIC_JS: return DC_IL_JS;
    default: return DC_IL_INVALID;
    }
}

static void dc_zy_lift_instruction(struct DCDisassemblerBackend *self, void *iobj, void *il_routinev, void *il_basic_block)
{
    DCDisassemblerBackend backend = *self;
    ZydisDisassembledInstruction *ins = iobj;
    DCLangBasicBlock *il_bb = il_basic_block;
    DCLangRoutine *il_routine = il_routinev;

    switch (ins->info.mnemonic) {
    case ZYDIS_MNEMONIC_MOV:
    case ZYDIS_MNEMONIC_LEA:
        if (ins->operands[0].reg.value == ZYDIS_REGISTER_RBP && ins->operands[1].reg.value == ZYDIS_REGISTER_RSP)
            break;
        il_load(backend, il_routine, il_bb, &ins->operands[1]);
        il_store(backend, il_routine, il_bb, &ins->operands[0]);
        break;
    case ZYDIS_MNEMONIC_ADD:
    case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_SHL:
        il_load(backend, il_routine, il_bb, &ins->operands[0]);
        il_load(backend, il_routine, il_bb, &ins->operands[1]);
        add_ins(&il_bb->instructions, (DCLangInstruction){
                .opcode = dc_zy_to_il_opcode(ins->info.mnemonic), .size = ins->operands[0].size });
        il_store(backend, il_routine, il_bb, &ins->operands[0]);
        break;
    case ZYDIS_MNEMONIC_CMP:
        il_load(backend, il_routine, il_bb, &ins->operands[1]);
        il_load(backend, il_routine, il_bb, &ins->operands[0]);
        add_ins(&il_bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_CMP, .size = ins->operands[0].size });
        break;
    case ZYDIS_MNEMONIC_NEG:
        il_load(backend, il_routine, il_bb, &ins->operands[0]);
        add_ins(&il_bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_NEG, .size = ins->operands[0].size });
        il_store(backend, il_routine, il_bb, &ins->operands[0]);
        break;
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JNB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JNBE:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_JNL:
    case ZYDIS_MNEMONIC_JNLE:
    case ZYDIS_MNEMONIC_JNS:
        il_bb->go_to_true = (void*)self->instruction_get_jump_target(self, ins);
        il_bb->go_to = (void*)self->instruction_get_jump_passed(self, ins);
        add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = dc_zy_to_il_opcode(ins->info.mnemonic) });
        break;
    case ZYDIS_MNEMONIC_JMP:
        il_bb->go_to = (void*)self->instruction_get_jump_target(self, ins);
        add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_JMP });
        break;
    case ZYDIS_MNEMONIC_CALL:
        add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_CALL, .immediate = self->instruction_get_jump_target(self, ins) });
        add_ins(&il_bb->instructions, (DCLangInstruction){ .opcode = DC_IL_STORE, .variable = NULL, .size = 32 });
        break;
    case ZYDIS_MNEMONIC_RET:
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

static DCDisassemblerBackend DC_DisassemblerZydis(int mode)
{
    if (mode < ZYDIS_MACHINE_MODE_LONG_64 || mode > ZYDIS_MACHINE_MODE_MAX_VALUE)
        assert(false && "bad mode");

    DCZydisData *data = malloc(sizeof(DCZydisData));
    data->mode = mode;

    return (DCDisassemblerBackend){
        .backend_dependent_data = data,
        .instruction_is_jump = dc_zy_instruction_is_jump,
        .instruction_is_jcc = dc_zy_instruction_is_jcc,
        .instruction_is_call = dc_zy_instruction_is_call,
        .instruction_is_ret = dc_zy_instruction_is_ret,
        .instruction_get_jump_target = dc_zy_instruction_get_jump_target,
        .instruction_get_jump_passed = dc_zy_instruction_get_jump_passed,
        .instruction_get_address = dc_zy_instruction_get_address,
        .instruction_get_operand = dc_zy_instruction_get_operand,
        .operand_get_type = dc_zy_operand_get_type,
        .operand_get_bitsize = dc_zy_operand_get_bitsize,
        .operand_register_index = dc_zy_operand_register_index,
        .operand_register_largest_enclosing_index = dc_zy_operand_register_largest_enclosing_index,
        .operand_memory_base_register_index = dc_zy_operand_memory_base_register_index,
        .operand_memory_disp = dc_zy_operand_memory_disp,
        .operand_is_stack_var = dc_zy_operand_is_stack_var,
        .operand_is_ret_val = dc_zy_operand_is_ret_val,
        .operand_immediate_value = dc_zy_operand_immediate_value,
        .operand_cmp = dc_zy_operand_cmp,
        .lift_instruction = dc_zy_lift_instruction
    };
}

#endif /* LIBDECOMP_BACKEND_ZYDIS_H */
