#include <libdecomp/libdecomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libdecomp/backend.h"
#include "native/basic_block.h"
#include "dynarr.h"
#include "visitor.h"
#include <libdecomp/formatter.h>

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define min(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b;       \
})

/*
 * to-do: find better way of doing this
 */
#define BUFFER_DEFAULT_LENGTH 64

char str_scope[3][16] = {
    "unscoped",
    "truth",
    "false"
};

void add_ins(DCLangInstruction **root, DCLangInstruction ins)
{
    ins.next = NULL;
    memcpy(dynarr_alloc((void**)root, sizeof(DCLangInstruction)), &ins, sizeof(ins));
}

static inline DCLangVariable *il_get_variable(DCDisassemblerBackend backend, DCLangRoutine *routine, void *operand, bool is_param)
{
    int i = 0;
    for (DCLangVariable *variable = routine->variables; variable; variable = variable->next, i++) {
        if (backend.operand_cmp(&backend, variable->native_operand, operand))
            return variable;
    }

    if (is_param)
        routine->n_params++;

    DCLangVariable *variable = dynarr_alloc((void**)&routine->variables, sizeof(DCLangVariable));
    variable->index = i;
    variable->size = backend.operand_get_bitsize(&backend, operand);
    variable->next = NULL;
    variable->is_param = is_param;
    variable->native_operand = operand;

    return variable;

    /*return memcpy(dynarr_alloc((void**)&routine->variables, sizeof(DCLangVariable)),*/
    /*              &(DCLangVariable){*/
    /*                  .next = NULL,*/
    /*                  .native_operand = *operand,*/
    /*                  .index = i,*/
    /*                  .size = backend.operand_get_bitsize(&backend, operand),*/
    /*                  .is_param = is_param*/
    /*              },*/
    /*              sizeof(DCLangVariable));*/
}

static inline void il_load_address(DCDisassemblerBackend backend, DCLangRoutine *routine, DCLangBasicBlock *bb, void *operand)
{
    add_ins(&bb->instructions, (DCLangInstruction){
            .opcode = DC_IL_LOAD_REG, .variable = il_get_variable(backend, routine, operand, false), .size = 8 });
    add_ins(&bb->instructions, (DCLangInstruction){
            .opcode = DC_IL_LOAD_IMM, .immediate = backend.operand_memory_disp(&backend, operand), .size = 8 });
    add_ins(&bb->instructions, (DCLangInstruction){
            .opcode = DC_IL_ADD, .size = 8 });
}

void il_load(DCDisassemblerBackend backend, DCLangRoutine *routine, DCLangBasicBlock *bb, void *operand)
{
    switch (backend.operand_get_type(&backend, operand)) {
    case DC_DISASM_OPERAND_IMM:
        add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_LOAD_IMM, .immediate = backend.operand_immediate_value(&backend, operand), .size = backend.operand_get_bitsize(&backend, operand) });
        break;
    case DC_DISASM_OPERAND_REG:
        add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_LOAD_REG, .variable = il_get_variable(backend, routine, operand, true), .size = backend.operand_get_bitsize(&backend, operand) });
        break;
    case DC_DISASM_OPERAND_MEM:
        if (backend.operand_is_stack_var(&backend, operand)) {
            add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_LOAD_REG,
                .variable = il_get_variable(backend, routine, operand, false), 
                .size = backend.operand_get_bitsize(&backend, operand) });
            return;
        }
        /* check if variable referenced already exists, likely does */
        {
            int idx = backend.operand_register_largest_enclosing_index(&backend, backend.operand_memory_base_register_index(&backend, operand));
            for (DCLangVariable *v = routine->variables; v; v = v->next) {
                int type = backend.operand_get_type(&backend, v->native_operand);
                if (type != DC_DISASM_OPERAND_REG) 
                    continue;
                
                int v_idx = backend.operand_register_largest_enclosing_index(&backend, backend.operand_register_index(&backend, v->native_operand));
                if (v_idx == idx) {
                    il_load_address(backend, routine, bb, v->native_operand);
                    add_ins(&bb->instructions, (DCLangInstruction){
                            .opcode = DC_IL_READ, .size = backend.operand_get_bitsize(&backend, operand) });
                    return;
                }
            }
        }

        il_load_address(backend, routine, bb, operand);
        add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_READ, .size = backend.operand_get_bitsize(&backend, operand) });
        break;
    default:
        break;
    }
}

void il_store(DCDisassemblerBackend backend, DCLangRoutine *routine, DCLangBasicBlock *bb, void *operand)
{
    switch (backend.operand_get_type(&backend, operand)) {
    case DC_DISASM_OPERAND_REG:
        add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_STORE, .variable = il_get_variable(backend, routine, operand, false), .size = backend.operand_get_bitsize(&backend, operand) });
        break;
    case DC_DISASM_OPERAND_MEM:
        if (backend.operand_is_stack_var(&backend, operand)) {
            add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_STORE,
                .variable = il_get_variable(backend, routine, operand, false), 
                .size = backend.operand_get_bitsize(&backend, operand) });

            return;
        }
        /* check if variable referenced already exists, likely does */
        {
            int idx = backend.operand_register_largest_enclosing_index(&backend, backend.operand_memory_base_register_index(&backend, operand));
            for (DCLangVariable *v = routine->variables; v; v = v->next) {
                int type = backend.operand_get_type(&backend, v->native_operand);
                if (type != DC_DISASM_OPERAND_REG) 
                    continue;
                
                int v_idx = backend.operand_register_largest_enclosing_index(&backend, backend.operand_register_index(&backend, v->native_operand));
                if (v_idx == idx) {
                    il_load_address(backend, routine, bb, v->native_operand);
                    add_ins(&bb->instructions, (DCLangInstruction){
                            .opcode = DC_IL_WRITE, .size = backend.operand_get_bitsize(&backend, operand) });
                    return;
                }
            }
        }

        il_load_address(backend, routine, bb, operand);
        add_ins(&bb->instructions, (DCLangInstruction){
                .opcode = DC_IL_WRITE, .size = backend.operand_get_bitsize(&backend, operand) });
        break;
    default:
        break;
    }    
}

typedef struct DCStackElement {
    struct DCStackElement *next;
    char string[BUFFER_DEFAULT_LENGTH];
} DCStackElement;

void dc_stack_push(DCStackElement **stack, DCStackElement **last, char *data)
{
    *last = dynarr_alloc((void**)stack, sizeof(DCStackElement));
    strncpy((*last)->string, data, BUFFER_DEFAULT_LENGTH);
}

void dc_stack_pop(DCStackElement **stack, DCStackElement **last, char *out_data)
{
    strncpy(out_data, (*last)->string, BUFFER_DEFAULT_LENGTH);
    dynarr_free_element((void**)stack, *last);

    if (*stack != NULL)
        for (*last = *stack; (*last)->next; *last = (*last)->next);
}

static void il2strop(DCLangOpcodeEnum op, char *str)
{
    switch (op) {
    case DC_IL_ADD: strcpy(str, "+"); return;
    case DC_IL_SUB: strcpy(str, "-"); return;
    case DC_IL_MUL: strcpy(str, "*"); return;
    case DC_IL_DIV: strcpy(str, "/"); return;
    case DC_IL_AND: strcpy(str, "&"); return;
    case DC_IL_OR: strcpy(str, "|"); return;
    case DC_IL_XOR: strcpy(str, "^"); return;
    case DC_IL_SHL: strcpy(str, "<<"); return;
    case DC_IL_SHR: strcpy(str, ">>"); return;
    case DC_IL_JZ:    strcpy(str, "=="); return;
    case DC_IL_JNZ:   strcpy(str, "!="); return;
    case DC_IL_JB:    strcpy(str, "<");  return;
    case DC_IL_JNB:   strcpy(str, ">="); return;
    case DC_IL_JBE:   strcpy(str, "<="); return;
    case DC_IL_JNBE:  strcpy(str, ">");  return;
    case DC_IL_JL:    strcpy(str, "<");  return;
    case DC_IL_JLE:   strcpy(str, "<="); return;
    case DC_IL_JNL:   strcpy(str, ">="); return;
    case DC_IL_JNLE:  strcpy(str, ">");  return;
    case DC_IL_JS:    strcpy(str, "<"); return;
    case DC_IL_JNS:    strcpy(str, ">="); return;
    default: strcpy(str, "??");
    }
}

static void il2strop_opposite(DCLangOpcodeEnum op, char *str)
{
    switch (op) {
    case DC_IL_JZ:    strcpy(str, "!="); return;  // opposite of ==
    case DC_IL_JNZ:   strcpy(str, "=="); return;  // opposite of !=
    case DC_IL_JB:    strcpy(str, ">="); return;  // opposite of 
    case DC_IL_JNB:   strcpy(str, "<");  return;  // opposite of >=
    case DC_IL_JBE:   strcpy(str, ">");  return;  // opposite of <=
    case DC_IL_JNBE:  strcpy(str, "<="); return;  // opposite of >
    case DC_IL_JL:    strcpy(str, ">="); return;  // opposite of 
    case DC_IL_JLE:   strcpy(str, ">");  return;  // opposite of <=
    case DC_IL_JNL:   strcpy(str, "<");  return;  // opposite of >=
    case DC_IL_JNLE:  strcpy(str, "<="); return;  // opposite of >
    default: strcpy(str, "??");
    }
}

static inline void *il_resolve(DCLangBasicBlock *basic_blocks, void *vaddress)
{
    uint64_t address = (uint64_t)vaddress;

    for (DCLangBasicBlock *bb = basic_blocks; bb; bb = bb->next) {
        if (address >= bb->native_start_va && address < bb->native_end_va) 
            return bb;
    }

    return NULL;
}

static inline void *il_resolve_routine(DCProgram *program, uint64_t address)
{
    for (DCLangRoutine *routine = program->lang_routines; routine; routine = routine->next) {
        if (address >= routine->basic_blocks[0].native_start_va && address < routine->basic_blocks[0].native_end_va)
            return routine;
    }

    return NULL;
}

void bb_visit(DCVisitor *visit, DCLangBasicBlock *bb)
{
    if (bb == NULL) return;
    if (!dc_visitor_add(visit, bb->native_start_va)) return;
    bb_visit(visit, bb->go_to);
}

DCLangBasicBlock* find_earliest_merge_point(DCLangBasicBlock *root, DCLangBasicBlock* block1, DCLangBasicBlock* block2) 
{
    DCVisitor *visit1 = dc_visitor_create(32); 
    DCVisitor *visit2 = dc_visitor_create(32);
    
    bb_visit(visit1, block1->go_to);  
    bb_visit(visit2, block2->go_to); 

    uint64_t *c1 = dc_visitor_get_compressed(visit1);
    uint64_t *c2 = dc_visitor_get_compressed(visit2);

    uint64_t m1 = UINT64_MAX, m2 = UINT64_MAX;
    for (int i = 0; i < visit1->count; i++) 
        if (c1[i] >= block1->native_start_va && c1[i] >= block2->native_start_va) m1 = min(m1, c1[i]);
    for (int i = 0; i < visit2->count; i++) 
        if (c2[i] >= block1->native_start_va && c2[i] >= block2->native_start_va) m2 = min(m2, c2[i]);

    free(visit1);
    free(visit2);
    free(c1);
    free(c2);

    return il_resolve(root, (void*)min(m1, m2));
}

static DCTraverserStopReason dc_traverser(DCControlNode **nodes, DCVisitor *visit, DCLangBasicBlock *root, DCLangBasicBlock *bb, DCControlNode *parent, DCLangBasicBlock *no_go, int indents, DCControlNodeScope scope)
{
    if (bb == NULL) return STOP_NULL_BB;
    if (bb == no_go) return STOP_MERGE_POINT;
    if (!dc_visitor_add(visit, bb->native_start_va)) return STOP_ALREADY_VISITED;

    /*char prefix[8*4] = "";*/
    /*for (int i = 0; i < indents; i++) ((uint32_t*)prefix)[i] = (uint32_t)'    ';*/

    DCControlNode *node = dynarr_alloc((void**)nodes, sizeof(DCControlNode));
    *node = (DCControlNode){
        .next = NULL,
        .next_in_level = NULL,
        .level = indents,
        .type = CONTROL_NODE_INVALID,
        .scope = scope,
        .bb = bb,
        .parent = parent
    };

    /*
     * conditional
     */
    if (bb->go_to && bb->go_to_true) {
        DCLangBasicBlock *merge_point = find_earliest_merge_point(root, bb->go_to, bb->go_to_true);
         
        /*printf("%s%s-conditional (%s): %p\n", prefix, bb->go_to == merge_point ? "single" : "dual", str_scope[scope], bb->native_start_va);*/
        /*printf("%d-%d merge_point = %p\n", 0, 2, merge_point->native_start_va);*/

        DCTraverserStopReason reason0 = dc_traverser(nodes, visit, root, bb->go_to_true, node, merge_point, indents+1, CONTROL_NODE_SCOPE_TRUE);
        DCTraverserStopReason reason1 = dc_traverser(nodes, visit, root, bb->go_to, node, merge_point, indents+1, CONTROL_NODE_SCOPE_FALSE);

        if (reason0 == STOP_ALREADY_VISITED || reason1 == STOP_ALREADY_VISITED) { 
            node->type = CONTROL_NODE_WHILE;
            /*printf("%s^^^ loop (%p)\n", prefix, bb->native_start_va); */
        } else {
            int n_bodies = 0;
            for (DCControlNode *n = node; n && n->bb != merge_point; n = n->next)
                if (n->level == node->level + 1) n_bodies++;

            node->type = n_bodies == 1 ? CONTROL_NODE_IF : CONTROL_NODE_IF_ELSE;
            /*printf("%s^^^ if (%p)\n", prefix, bb->native_start_va); */
        }

        /*
         * if we are only a single condition, then the false statement should be its own scope
         */
        if (node->type == CONTROL_NODE_WHILE) {
            for (DCControlNode *n = node; n; n = n->next) {
                if (n->level == node->level + 1 && n->scope == CONTROL_NODE_SCOPE_FALSE) {
                    n->level--;
                    n->scope = CONTROL_NODE_SCOPE_NONE;
                    for (DCControlNode *m = n; m; m = m->next)
                        m->level--;
                    break;
                }
            }
        }

        return dc_traverser(nodes, visit, root, merge_point, parent, no_go, indents, CONTROL_NODE_SCOPE_NONE);
    }
    else {
        node->type = CONTROL_NODE_BODY;
        /*printf("%sbody (%s): %p\n", prefix, str_scope[scope], bb->native_start_va);*/
        return dc_traverser(nodes, visit, root, bb->go_to, parent, no_go, indents, CONTROL_NODE_SCOPE_NONE);
    }
}

static DCControlNode *dc_traverse(DCLangBasicBlock *root)
{
    DCVisitor *visit = dc_visitor_create(32);
    DCControlNode *nodes = NULL;

    dc_traverser(&nodes, visit, root, root, NULL, NULL, 0, CONTROL_NODE_SCOPE_NONE);

    int max_level = 0;
    for (DCControlNode *n = nodes; n; n = n->next) { 
        // if (n->parent == NULL) n->level = max(0, n->level - 1);
        max_level = max(n->level, max_level); 
    }
    for (int i = 0; i <= max_level; i++) {
        DCControlNode *previous = NULL;
        for (DCControlNode *n = nodes; n; n = n->next) {
            /*if (i == 0) printf("level=%d\n", n->level);*/
            if (n->level != i) continue;
            if (!previous) previous = n;
            else {
                /*printf("level %d\n", i);*/
                previous->next_in_level = n;
                previous = n;
            }
        }
    }

    free(visit);
    return nodes;
}

static DCLangOpcodeEnum dc_eval(DCProgram *program, DCFormatterContext formatter, char *dst, size_t n, DCLangBasicBlock *il_bb, DCStackElement **stack, DCStackElement **last, int indents, char *cmp0, char *cmp1, bool out)
{
    char elem[BUFFER_DEFAULT_LENGTH], elem2[BUFFER_DEFAULT_LENGTH], elem3[BUFFER_DEFAULT_LENGTH];
    char op[3];

    DCLangOpcodeEnum jmp_op = -1;

    for (DCLangInstruction *i = il_bb->instructions; i; i = i->next) {
#if 0
        DC_FormatAppend(dst, n, "%s ", dc_lang_opcode_enum_str[i->opcode]);
        switch (i->opcode) {
        case DC_IL_LOAD_REG:
        case DC_IL_STORE:
            DC_FormatAppend(dst, n, "v%d", i->variable->index);
            break;
        default:
            break;
        }
        DC_FormatAppend(dst, n, "\n");
#endif

        switch (i->opcode) {
        case DC_IL_LOAD_REG:
            strcpy(elem, "");
            DC_FormatAppendVariable(&formatter, elem, sizeof(elem), i->variable);
            /*il_var_name(i->variable, elem);*/
            dc_stack_push(stack, last, elem);
            break;
        case DC_IL_LOAD_IMM:
            sprintf(elem, "%ld", i->immediate);
            dc_stack_push(stack, last, elem);
            break;
        case DC_IL_STORE:
            strcpy(elem, "");
            DC_FormatAppendVariable(&formatter, elem, sizeof(elem), i->variable);
            /*il_var_name(i->variable, elem);*/
            dc_stack_pop(stack, last, elem2);
            if (out) {
                DC_FormatIndent(&formatter, dst, n, indents);
                DC_FormatAppend(dst, n, formatter.assignment_format, elem, elem2, formatter.endline);
            }
            break;
        case DC_IL_READ:
            dc_stack_pop(stack, last, elem2);
            strcpy(elem, "");
            formatter.implementation.fmt_memory_location(&formatter, elem, sizeof(elem), elem2, i->size);
            /*sprintf(elem, "*(u%ld*)%s", i->size, elem2);*/
            dc_stack_push(stack, last, elem);
            break;
        case DC_IL_WRITE:
            dc_stack_pop(stack, last, elem2);
            dc_stack_pop(stack, last, elem);
            strcpy(elem3, "");
            formatter.implementation.fmt_memory_location(&formatter, elem3, sizeof(elem3), elem2, i->size);
            if (out) {
                DC_FormatIndent(&formatter, dst, n, indents);
                DC_FormatAppend(dst, n, formatter.assignment_format, elem3, elem, formatter.endline);
            }
            /*if (out) printf("%s*(u%ld*)%s = %s;\n", prefix, i->size, elem2, elem);*/
            break;
        case DC_IL_ADD:
        case DC_IL_SUB:
        case DC_IL_MUL:
        case DC_IL_DIV:
        case DC_IL_AND:
        case DC_IL_OR:
        case DC_IL_XOR:
        case DC_IL_SHL:
        case DC_IL_SHR:
            il2strop(i->opcode, op);
            dc_stack_pop(stack, last, elem2);
            dc_stack_pop(stack, last, elem3);
            sprintf(elem, formatter.arithmetic_format, elem3, op, elem2);
            dc_stack_push(stack, last, elem);
            break;
        case DC_IL_NEG:
            dc_stack_pop(stack, last, elem2);
            sprintf(elem, "-%s", elem2);
            dc_stack_push(stack, last, elem);
            break;
        case DC_IL_CMP:
            dc_stack_pop(stack, last, cmp0);
            dc_stack_pop(stack, last, cmp1);
            break;
        case DC_IL_JZ:
        case DC_IL_JNZ:
        case DC_IL_JB:
        case DC_IL_JNB:
        case DC_IL_JBE:
        case DC_IL_JNBE:
        case DC_IL_JL:
        case DC_IL_JLE:
        case DC_IL_JNL:
        case DC_IL_JNLE:
        case DC_IL_JNS:
        case DC_IL_JS:
            jmp_op = i->opcode;
            break;
        case DC_IL_CALL:
            if (out) {
                DCLangRoutine *routine = il_resolve_routine(program, i->immediate);

                strcpy(elem, "");

                /*
                 * to-do: function parameters
                 */
                
                DC_FormatAppendRoutine(&formatter, elem, sizeof(elem), routine);
                DC_FormatAppend(elem, sizeof(elem), "()");

                dc_stack_push(stack, last, elem);
                
                // DC_FormatAppend(dst, n, "%s%lx()%s", formatter.routine_prefix, i->immediate, formatter.endline);
                /*DC_FormatAppendRoutine(&formatter, dst, n, )*/
            }
            break;
        case DC_IL_RET:
            dc_stack_pop(stack, last, elem2);
            if (out) {
                /*DC_FormatAppend(dst, n, "\n");*/
                DC_FormatIndent(&formatter, dst, n, indents);
                DC_FormatAppend(dst, n, formatter.return_format, elem2, formatter.endline);
            }
            break;
        case DC_IL_PHI:
            il2strop(i->opcode, op);
            dc_stack_pop(stack, last, elem2);
            dc_stack_pop(stack, last, elem3);
            sprintf(elem, "phi(%s, %s)", elem3, elem2);
            dc_stack_push(stack, last, elem);
            break;
        default:
            break;
        }
    }

    return jmp_op;
}

DCControlNode *dc_emitter(DCProgram *program, DCFormatterContext formatter, char *dst, size_t n, DCControlNode *node, DCStackElement **stack, DCStackElement **last) 
{
    if (node == NULL) return NULL;

    DCLangBasicBlock *il_bb = node->bb;
    
    char op[4];
    char cmp0[BUFFER_DEFAULT_LENGTH], cmp1[BUFFER_DEFAULT_LENGTH];

    DCLangOpcodeEnum jmp_op = dc_eval(program, formatter, dst, n, il_bb, stack, last, node->level + 1, cmp0, cmp1, node->type != CONTROL_NODE_WHILE);
    
    if (node->type == CONTROL_NODE_IF_ELSE) {
        il2strop(jmp_op, op);
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_conditional_header(&formatter, dst, n, node->type, cmp0, cmp1, op);
        
        DCControlNode *next_node = dc_emitter(program, formatter, dst, n, node->next, stack, last);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);

        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_else_header(&formatter, dst, n);

        dc_emitter(program, formatter, dst, n, next_node, stack, last);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);
        
        return dc_emitter(program, formatter, dst, n, node->next_in_level, stack, last);
    }
    else if (node->type == CONTROL_NODE_IF) {
        if (node->next->scope == CONTROL_NODE_SCOPE_FALSE)
            il2strop_opposite(jmp_op, op);
        else
            il2strop(jmp_op, op);

        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_conditional_header(&formatter, dst, n, node->type, cmp0, cmp1, op);
        
        dc_emitter(program, formatter, dst, n, node->next, stack, last);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);

        return dc_emitter(program, formatter, dst, n, node->next_in_level, stack, last);
    }
    else if (node->type == CONTROL_NODE_WHILE) {
        il2strop(jmp_op, op);

        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_conditional_header(&formatter, dst, n, node->type, cmp0, cmp1, op);
        
        dc_emitter(program, formatter, dst, n, node->next, stack, last);
        dc_eval(program, formatter, dst, n, il_bb, stack, last, node->level + 2, cmp0, cmp1, true);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);
        return dc_emitter(program, formatter, dst, n, node->next_in_level, stack, last);
    }
    else if (node->scope == CONTROL_NODE_SCOPE_NONE) {
        if (node->next_in_level) {
            if (node->next_in_level->parent == node->parent)
                dc_emitter(program, formatter, dst, n, node->next_in_level, stack, last);
        }
        else dc_emitter(program, formatter, dst, n, node->next_in_level, stack, last);
    }

    if (node) return node->next;
    return NULL;
}

static inline bool il_holds_var(DCLangInstruction *i)
{
    return i->opcode == DC_IL_LOAD_REG || i->opcode == DC_IL_STORE;
}

static DCLangVariable *ssa_create_var(DCControlNode *node, DCLangVariable *parent)
{
    if (parent->ssa_parent != NULL) parent = parent->ssa_parent;
    DCLangVariable *result = dynarr_alloc((void**)&parent->ssa_list, sizeof(DCLangVariable));
    result->index = parent->ssa_last != NULL ? parent->ssa_last->index + 1 : 0;
    result->is_param = parent->is_param;
    result->size = parent->size;
    result->native_operand = parent->native_operand;
    result->ssa_parent = parent;
    parent->ssa_last = result;
    node->ssa_last_array[parent->index] = result;
    return result;
}

static DCLangVariable *ssa_get_var(DCControlNode *node, DCLangVariable *parent)
{
    if (parent->ssa_parent != NULL) parent = parent->ssa_parent;
    if (node->ssa_last_array[parent->index]) return node->ssa_last_array[parent->index];
    if (parent->ssa_last != NULL) return parent->ssa_last;
    return ssa_create_var(node, parent);
}

static void ssa_insert_phi(DCControlNode *node, DCLangVariable *og, DCLangVariable *potential)
{
    DCLangInstruction *phi_root = NULL;
    for (int i = 0; i < 4; i++)
        dynarr_alloc((void**)&phi_root, sizeof(DCLangInstruction));

    DCLangInstruction *push0 = phi_root;
    DCLangInstruction *push1 = phi_root->next;
    DCLangInstruction *phi = push1->next;
    DCLangInstruction *pop = phi->next;

    push0->opcode = DC_IL_LOAD_REG;
    push1->opcode = DC_IL_LOAD_REG;
    phi->opcode = DC_IL_PHI;
    pop->opcode = DC_IL_STORE;

    push0->variable = og;
    push1->variable = potential;
    pop->variable = ssa_create_var(node, og);

    pop->next = node->bb->instructions;
    node->bb->instructions = phi_root;
}

typedef struct SSAStackNode {
    struct SSAStackNode *next;
    DCControlNode *node;
} SSAStackNode;

typedef struct SSAStackVariable {
    struct SSAStackVariable *next;
    DCLangVariable *var;
} SSAStackVariable;

void ssa_stack_push_node(SSAStackNode **stack, SSAStackNode **last, DCControlNode *node)
{
    *last = dynarr_alloc((void**)stack, sizeof(SSAStackNode));
    (*last)->node = node;
}

void ssa_stack_pop_node(SSAStackNode **stack, SSAStackNode **last)
{
    dynarr_free_element((void**)stack, *last);

    if (*stack != NULL)
        for (*last = *stack; (*last)->next; *last = (*last)->next);
}

void ssa_stack_push_variable(SSAStackVariable **stack, SSAStackVariable **last, DCLangVariable *node)
{
    *last = dynarr_alloc((void**)stack, sizeof(SSAStackVariable));
    (*last)->var = node;
}

void ssa_stack_pop_variable(SSAStackVariable **stack, SSAStackVariable **last)
{
    dynarr_free_element((void**)stack, *last);

    if (*stack != NULL)
        for (*last = *stack; (*last)->next; *last = (*last)->next);
}

void dc_convert_to_ssa(DCLangRoutine *routine, DCControlNode *root)
{
    int n_variables = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next) n_variables++;
    
    SSAStackNode *stack_node = NULL;
    SSAStackNode *stack_last_node;

    SSAStackVariable *stack_var = NULL;
    SSAStackVariable *stack_last_var;

    DCControlNode *prev_l0 = root;

    for (DCControlNode *node = root; node; node = node->next) {
        node->ssa_last_array = calloc(n_variables, sizeof(DCLangVariable*));
        if (node->parent) { 
            memcpy(node->ssa_last_array, node->parent->ssa_last_array, n_variables * sizeof(DCLangVariable*));
        }
        else {
            memcpy(node->ssa_last_array, prev_l0->ssa_last_array, n_variables * sizeof(DCLangVariable*));
        }

        /*printf("copied: [ ");*/
        /*char scratch[8];*/
        /*for (int i = 0; i < n_variables; i++)*/
        /*    printf("%s ", node->ssa_last_array[i] ? il_var_name(node->ssa_last_array[i], scratch) : "-");*/
        /*printf("]\n");*/
        int n_skip = 0;

        /*if (node->type != CONTROL_NODE_BODY) {*/
        /*    if (node->next_in_level == NULL) {*/
        /*        DCControlNode *next_node = dynarr_alloc((void**)&node->next_in_level, sizeof(DCControlNode));*/
        /*        *next_node = (DCControlNode){*/
        /*            .next = NULL,*/
        /*            .next_in_level = NULL,*/
        /*            .level = node->level,*/
        /*            .type = CONTROL_NODE_BODY,*/
        /*            .scope = node->scope,*/
        /*            .bb = calloc(1, sizeof(DCLangBasicBlock)),*/
        /*            .parent = node->parent*/
        /*        };*/
        /**/
        /*        DCControlNode *insertion_point = node;*/
        /*        for (; insertion_point->next; insertion_point = insertion_point->next)*/
        /*            if (insertion_point->next->level < node->level)*/
        /*                break;*/
        /**/
        /*        DCControlNode *saved = insertion_point->next;*/
        /*        insertion_point->next = next_node;*/
        /*        next_node->next = saved;*/
        /*    }*/
        /**/
        /*    ssa_stack_push_node(&stack_node, &stack_last_node, node->next_in_level);*/
        /*}*/
        /**/
        /*if (stack_last_node->node == node) {*/
        /*    DCLangVariable *v0, *v1;*/
        /*    v0 = stack_last_var->var;*/
        /*    ssa_stack_pop_variable(&stack_var, &stack_last_var);*/
        /*    v1 = stack_last_var->var;*/
        /*    ssa_stack_pop_variable(&stack_var, &stack_last_var);*/
        /**/
        /*    ssa_insert_phi(node, v0, v1); */
        /*    ssa_stack_pop_node(&stack_node, &stack_last_node);*/
        /**/
        /*    n_skip += 4;*/
        /*}*/
        /*printf("n_skip = %d\n", n_skip);*/
        for (DCLangInstruction *i = node->bb->instructions; i; i = i->next) {
            if (n_skip-- > 0) continue;
            if (i->opcode == DC_IL_LOAD_REG) i->variable = ssa_get_var(node, i->variable);
            else if (i->opcode == DC_IL_STORE) i->variable = ssa_create_var(node, i->variable);
        }

        /*printf("[ ");*/
        /*for (int i = 0; i < n_variables; i++) {*/
        /*    char scratch[8];*/
        /*    if (node->ssa_last_array[i])*/
        /*        ssa_stack_push_variable(&stack_var, &stack_last_var, node->ssa_last_array[i]);*/
        /*        /*printf("%s ", il_var_name(node->ssa_last[i], scratch));*/
        /*}*/
        /*printf("]\n");*/

        if (node->level == 0) prev_l0 = node;
    }
}

void dc_optimizer_remove_dead_variables(DCDisassemblerBackend backend, DCLangRoutine *routine)
{
    int n_variables = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next) n_variables++;

    bool read[n_variables];
    bool write[n_variables];
    DCLangVariable *vars[n_variables];

    int j = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next) vars[j++] = v;

    memset(read, 0, n_variables * sizeof(bool));
    memset(write, 0, n_variables * sizeof(bool));

    for (DCLangBasicBlock *bb = routine->basic_blocks; bb; bb = bb->next) {
        for (DCLangInstruction *i = bb->instructions; i; i = i->next) {
            switch (i->opcode) {
            case DC_IL_LOAD_REG: read[i->variable->index] = true; break;
            case DC_IL_STORE: write[i->variable->index] = true; break;
            default: break;
            }
        }
    }

    // for (int i = 0; i < n_variables; i++) {
    //     printf("var%d read? %s\n", vars[i]->index, read[vars[i]->index] ? "yes" : "no");
    // }
    
    for (DCLangBasicBlock *bb = routine->basic_blocks; bb; bb = bb->next) {
        for (DCLangInstruction *i = bb->instructions; i;) {
            switch (i->opcode) {
            /*case DC_IL_LOAD_REG:*/
            case DC_IL_STORE:
                if (!read[i->variable->index] /*&& !backend.operand_is_ret_val(&backend, i->variable->native_operand)*/) {
                    DCLangInstruction *n = i->next;
                    dynarr_free_element((void**)&bb->instructions, i);
                    i = n;
                    break;
                }
            default: i = i->next; break;
            }
        }
    }

    for (int i = 0; i < n_variables; i++) {
        if (!read[i] /*&& !backend.operand_is_ret_val(&backend, vars[i]->native_operand)*/) {
            if (backend.operand_is_ret_val(&backend, vars[i]->native_operand))
                routine->retval = NULL;
            dynarr_free_element((void**)&routine->variables, vars[i]);
        }
    }

    j = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next)
        v->index = j++;
}

void dc_optimizer_remove_dead_code(DCLangRoutine *routine)
{
    int n_variables = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next) n_variables++;

    DCLangInstruction *ins[n_variables];

    for (DCLangBasicBlock *bb = routine->basic_blocks; bb; bb = bb->next) {
        memset(ins, 0, n_variables * sizeof(DCLangInstruction*));
        
        for (DCLangInstruction *i = bb->instructions; i; i = i->next) {
            if (i->opcode == DC_IL_STORE) {
                if (ins[i->variable->index])
                    dynarr_free_element((void**)&bb->instructions, ins[i->variable->index]);
                ins[i->variable->index] = i;
            }
            else if (i->opcode == DC_IL_LOAD_REG) {
                ins[i->variable->index] = NULL;
            }
        }
    }
}

void dc_optimizer_remove_dead_common_code(DCLangRoutine *routine)
{
    for (DCLangBasicBlock *bb = routine->basic_blocks; bb; bb = bb->next) {
        for (DCLangInstruction *i = bb->instructions; i;) {
            DCLangInstruction *i0 = i;
            DCLangInstruction *i1 = i->next;

            if (i1 == NULL)
                break;

            if (i0->opcode == DC_IL_LOAD_REG && i1->opcode == DC_IL_STORE)
                if (i0->variable == i1->variable) {
                    DCLangInstruction *next = i1->next;
                    dynarr_free_element((void**)&bb->instructions, i0);
                    dynarr_free_element((void**)&bb->instructions, i1);
                    i = next;
                    continue;
                }

            i = i1;
        }
    }
}

void dc_optimizer_simplify_shifts(DCLangRoutine *routine)
{
    DCLangInstruction *last_two_loads[2] = { NULL };

    for (DCLangBasicBlock *bb = routine->basic_blocks; bb; bb = bb->next) {
        for (DCLangInstruction *i = bb->instructions; i; i = i->next) {
            if (i->opcode == DC_IL_LOAD_REG || i->opcode == DC_IL_LOAD_IMM) {
                last_two_loads[1] = last_two_loads[0];
                last_two_loads[0] = i;
                continue;
            }

            if (last_two_loads[1] == NULL) continue;

            if (last_two_loads[0]->opcode == DC_IL_LOAD_IMM && last_two_loads[1]->opcode == DC_IL_LOAD_REG) {
                switch (i->opcode) {
                case DC_IL_SHL:
                case DC_IL_SHR:
                    i->opcode = i->opcode == DC_IL_SHL ? DC_IL_MUL : DC_IL_DIV;
                    last_two_loads[0]->immediate = (1 << last_two_loads[0]->immediate);
                    break;
                default:
                    break;
                }
            }
        }
    }
}

#include <assert.h>

struct var_history {
    DCLangInstruction *ins[32];
    int n_ins;
};

static void var_history_add(struct var_history *var, DCLangInstruction *ins)
{
    assert(var->n_ins < 32);
    var->ins[var->n_ins++] = ins;
}

void dc_optimizer_copy_propagation(DCControlNode *root, DCLangRoutine *routine) {
    int n_variables = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next, n_variables++);

    /*
     * var_history contains the instructions which need to be executed in order for
     * us to evaluate the value of some element within the stack. this optimization
     * pass essentially requires us to evaluate the IL code, but not execute it fully;
     *
     * instead of calculating values within the stack, the stack consists of "histories,"
     * these historys allow us to determine how we could evaluate this element if the
     * values were known (we obviously do not know the value of something like arg0)
     *
     * take for example this program:
     * load v0
     * load v1
     * add
     * store v2
     * load v2
     * load v3
     * add
     * store v4
     *
     * this program is essentially:
     * v2 = (v0 + v1)
     * v4 = (v2 + v3)
     *
     * if we wish to perform copy propagation, we can propagate the value of v2 to the
     * v4 expression, like so:
     *
     * v4 = ((v0 + v1) + v3)
     *
     * however, how do we even get this result? this is where var_history comes in.
     * we maintain two histories:
     * 1. variable history: each variable within the routine is assigned its own history
     *                      when we reach an instruction like 'store', we can write its
     *                      tracked history to this variable history
     * 2. stack history: this history consists of the histories of elements within the
     *                   stack itself. we can construct this history until we reach a
     *                   store, in which the history will move off of the stack and into
     *                   a variable specific history
     *
     * lets go through our example:
     * -------------------------------------------------------------------------------------
     * load v0
     * STACK: { { v0 } }
     * VARS: { v0{}, v1{}, v2{}, v3{}, v4{} }
     *
     * load v1
     * STACK { { load v0 }, { load v1 } }
     *
     * add
     * STACK { { load v0, load v1, add } } << HISTORIES FROM THE PREVIOUS TWO ELEMENTS WERE
     *                                        COMBINED INTO ONE HISTORY, WITH THE ADD OPCODE
     *                                        BEING ADDED TO THE NEW HISTORY
     *
     * store v2
     * STACK { }
     * VARS: { v0{}, v1{}, v2{ load v0, load v1, add }, v4{} } << NOTICE THE ELEMENT WAS MOVED
     *                                                            OFF OF THE STACK AND INTO V2
     *
     * load v2
     * REMOVE AND REPLACE THIS INSTRUCTION WITH HISTORY PRESENT V2
     * RESTART FROM BEGINNING OF BASIC BLOCK
     * --------------------------------------------------------------------------------------
     *
     * essentially, the same is repeated for v4. its important to note that when we encounter
     * an instruction like add, which takes in two operands from the stack, that we merge the
     * histories of the last two elements on the stack, in order for our add instruction to
     * maintain correctness. otherwise, we may only copy a partial definition, like { load v1, add },
     * which is obviously incorrect as it ignored load v0, overwriting it with load v1.
     */

    struct var_history variables[n_variables];
    struct var_history stack[32];
    int sp;

    bool changed_in_iteration = true;
    while (changed_in_iteration) {
        changed_in_iteration = false;
        for (DCControlNode *node = root; node && !changed_in_iteration; node = node->next) {
            memset(variables, 0, sizeof(struct var_history) * n_variables);
            memset(stack, 0, sizeof(struct var_history) * 32);
            sp = 0;

            DCLangInstruction *prev_ins = NULL;
            DCLangInstruction *current_ins = node->bb->instructions;
            while (current_ins && !changed_in_iteration) {
                DCLangInstruction *next_ins = current_ins->next;
                const DCLangVariable *iv = current_ins->variable;
                assert(sp >= 0 && sp < 32);

                switch (current_ins->opcode) {
                case DC_IL_LOAD_IMM:
                case DC_IL_CALL:
                    var_history_add(&stack[sp++], current_ins);
                    break;
                case DC_IL_LOAD_REG:
                    if (iv && variables[iv->index].n_ins > 0) {
                        // circular dependency check
                        // TODO fix arm64 issue
                        if (variables[iv->index].n_ins == 1
                            && variables[iv->index].ins[0]->opcode == DC_IL_LOAD_REG
                            && variables[variables[iv->index].ins[0]->variable->index].n_ins == 1
                            && variables[variables[iv->index].ins[0]->variable->index].ins[0]->variable == iv) {
                            variables[iv->index].n_ins = 0;
                            variables[variables[iv->index].ins[0]->variable->index].n_ins = 0;
                            break;
                        }

                        DCLangInstruction *new_seq_head = NULL, *new_seq_tail = NULL;
                        for (int j = 0; j < variables[iv->index].n_ins; j++) {
                            DCLangInstruction *original_hist_ins = variables[iv->index].ins[j];
                            DCLangInstruction *dst = dynarr_alloc((void**)&new_seq_head, sizeof(DCLangInstruction));
                            memcpy(dst, original_hist_ins, sizeof(DCLangInstruction));
                            dst->next = NULL;
                            if (!new_seq_head) new_seq_head = dst;
                            if (new_seq_tail) new_seq_tail->next = dst;
                            new_seq_tail = dst;
                        }

                        if (prev_ins) prev_ins->next = new_seq_head;
                        else node->bb->instructions = new_seq_head;

                        new_seq_tail->next = next_ins;
                        free(current_ins);

                        /* current_ins = new_seq_head; */
                        /* next_ins = new_seq_head->next; */
                        changed_in_iteration = true;
                    } else {
                        var_history_add(&stack[sp++], current_ins);
                    }
                    break;
                case DC_IL_STORE:
                    assert(sp != 0);
                    assert(iv);
                    variables[iv->index] = stack[--sp];
                    stack[sp].n_ins = 0;
                    break;
                case DC_IL_ADD:
                case DC_IL_SUB:
                case DC_IL_MUL:
                case DC_IL_DIV:
                case DC_IL_SHL:
                case DC_IL_SHR:
                case DC_IL_AND:
                case DC_IL_OR:
                case DC_IL_XOR:
                case DC_IL_WRITE:
                    assert(sp >= 2);
                    {
                        struct var_history *hist_operand2 = &stack[sp - 1];
                        struct var_history *hist_operand1 = &stack[sp - 2];

                        assert(hist_operand1->n_ins + hist_operand2->n_ins + 1 <= 32);

                        // merge histories; hist_operand1 = hist_operand1 + hist_operand2 + current_instruction
                        for (int k = 0; k < hist_operand2->n_ins; k++) {
                            var_history_add(hist_operand1, hist_operand2->ins[k]);
                        }
                        var_history_add(hist_operand1, current_ins); // add the instruction itself
                        hist_operand2->n_ins = 0; // clear consumed operand 2 history
                        sp--; // pop one operand as result is written into hist_operand1's original slot
                    }
                    break;
                case DC_IL_NEG:
                case DC_IL_READ:
                    assert(sp >= 1);
                    var_history_add(&stack[sp-1], current_ins);
                    break;
                case DC_IL_JMP ... DC_IL_JS:
                    break;
                default:
                    break;
                }
                prev_ins = current_ins;
                current_ins = next_ins;
            }
        }
    }
}

struct var_history_2d {
    DCLangInstruction *ins[512][256];
    int n_ins[512];
    int n_new;
};

static void var_history_2d_add(struct var_history_2d *var, DCLangInstruction *ins)
{
    assert(var->n_ins[var->n_new] < 256);
    var->ins[var->n_new][var->n_ins[var->n_new]++] = ins;
}

static void var_history_2d_new(struct var_history_2d *var, DCLangInstruction *ins)
{
    assert(var->n_new < 512);
    var->n_new++;
}

void dc_optimizer_remove_dead_code_v2(DCControlNode *root, DCLangRoutine *routine)
{
    int n_variables = 0;
    for (DCLangVariable *v = routine->variables; v; v = v->next, n_variables++);

    struct var_history_2d variables[n_variables];
    memset(variables, 0, sizeof(variables));
    
    for (DCControlNode *node = root; node; node = node->next) {
        DCLangInstruction *prev = NULL;
        for (DCLangInstruction *i = node->bb->instructions; i;) {
            const DCLangVariable *iv = i->variable;
            
            switch (i->opcode) {
            case DC_IL_LOAD_REG:
                var_history_2d_add(&variables[iv->index], i);
                break;
            case DC_IL_STORE:
                var_history_2d_new(&variables[iv->index], i);
                break;
            default:
                break;
            }
            
            prev = i;
            i = i->next;
        }
    }

    /* for (int j = 0; j < n_variables; j++) { */
    /*     printf("var%d stats:\n", j); */
    /*     if (variables[j].n_new < 32) { */
    /*         for (int i = 1; i < variables[j].n_new + 1; i++) { */
    /*             printf("the %d stored value was used %d times\n", i, variables[j].n_ins[i]); */
    /*         } */
    /*     } */
    /*     else printf("cant print stats; n_new = %d\n", variables[j].n_new); */
    /* } */
}

static void print_routine(DCProgram *program, DCFormatterContext formatter, DCDisassemblerBackend backend, DCLangRoutine *il_routine, DCControlNode *nodes, char *dst, size_t n)
{
    formatter.implementation.fmt_function_header(&formatter, dst, n, il_routine);

    DCStackElement *stack = NULL, *last = NULL;
    dc_emitter(program, formatter, dst, n, nodes, &stack, &last);

    formatter.implementation.fmt_header_epilogue(&formatter, dst, n);
}

static int qsort_cmp(const void *a, const void *b)
{
    uint64_t x = *(uint64_t*)a;
    uint64_t y = *(uint64_t*)b;
    return (x > y) - (x < y);
}

DCNativeRoutine *dc_native_routine_create(DCProgram *program,
                                          DCNativeRoutine data)
{
    DCNativeRoutine *rout = dynarr_alloc((void**)&program->native_routines, 
                                            sizeof(DCNativeRoutine));
    
    memcpy(rout, &data, sizeof(DCNativeRoutine));
    rout->next = NULL;
    return rout;
}

static void split_routines(DCProgram *program)
{
    DCDisassemblerBackend backend = *program->disasm_backend;
    
    DCVisitor *visit = dc_visitor_create(128);
    uintptr_t start_va = -1;
    uintptr_t end_va = 0;

    for (size_t i = 0; i < program->query_len; i++) {
        void *ins = program->query_callback(program->query_ctx, i);
        end_va = backend.instruction_get_address(&backend, ins);
        if (start_va == -1) { start_va = end_va; dc_visitor_add(visit, end_va); }

        if (backend.instruction_is_call(&backend, ins))
            dc_visitor_add(visit, backend.instruction_get_jump_target(&backend, ins));

        if (backend.instruction_is_ret(&backend, ins) && i + 1 < program->query_len)
            dc_visitor_add(visit, backend.instruction_get_address(&backend, program->query_callback(program->query_ctx, i + 1)));
    }

    uint64_t *addresses = dc_visitor_get_compressed(visit);
    qsort(addresses, visit->count, sizeof(uint64_t), qsort_cmp);

    DCNativeRoutine *current = dc_native_routine_create(program, (DCNativeRoutine){
        .start_va = start_va
    });

    size_t last_instruction_idx = 0;
    for (int i = 0; i < visit->count; i++) {
        /*
         * this is a really stupid hack (to-do), mostly bc im lazy
         */
        uint64_t end_address = i + 1 < visit->count ? addresses[i + 1] : backend.instruction_get_address(&backend, program->query_callback(program->query_ctx, program->query_len - 1)); 

        current->query_begin = last_instruction_idx;
        current->end_va = end_address;
        for (; last_instruction_idx < program->query_len; last_instruction_idx++) {
            void *ins = program->query_callback(program->query_ctx, last_instruction_idx);
            current->query_end = last_instruction_idx;
            if (backend.instruction_get_address(&backend, ins) >= end_address)
                break;
        }

        if (!(i+1<visit->count)) current->query_end++;

        current = dc_native_routine_create(program, (DCNativeRoutine){
            .start_va = end_address
        });
    }

    dynarr_free_element((void**)&program->native_routines, current);
    free(addresses);
    free(visit);
}

DCError DC_ProgramDecompile(DCProgram *program,
                            char *dst,
                            const size_t n)
{
    if (program->disasm_backend == NULL) return DC_ERROR_PROGRAM_MISSING_BACKEND;
    if (program->formatter == NULL) return DC_ERROR_PROGRAM_MISSING_FORMATTER;

    DCDisassemblerBackend backend = *program->disasm_backend;
    DCFormatterContext formatter = *program->formatter;

    for (int i = 0; i < sizeof(formatter.implementation) / sizeof(size_t); i++)
        if (((size_t*)&formatter.implementation)[i] == (size_t)NULL)
            return DC_ERROR_MISSING_FMT_CALLBACK;

    for (int i = 0; i < sizeof(backend) / sizeof(size_t); i++)
        if (((size_t*)&backend)[i] == (size_t)NULL)
            return DC_ERROR_MISSING_BACKEND_CALLBACK;

    split_routines(program);

    /*
     * to-do: add a function which splits the initial big block into routines:
     *    - one routine is formed at the starting address
     *    - call instructions imm (callees)
     *    - possibly after ret instructions, or if given an ABI hint like SYSV
     *      where we can detect prologues and epilogues
     */

    for (DCNativeRoutine *routine = program->native_routines; routine; routine = routine->next) {
        dc_native_basic_block_decompose(backend, routine, program);

        DCLangRoutine *il_routine = dynarr_alloc((void**)&program->lang_routines, sizeof(DCLangRoutine));

        for (DCNativeBasicBlock *basic_block = routine->basic_blocks; basic_block; basic_block = basic_block->next) {
            DCLangBasicBlock *il_bb = dynarr_alloc((void**)&il_routine->basic_blocks, 
                                                   sizeof(DCLangBasicBlock));

            il_bb->native_start_va = basic_block->start_va;
            il_bb->native_end_va = basic_block->end_va;

            for (size_t i = basic_block->query_begin; i < basic_block->query_end; i++)
                backend.lift_instruction(&backend, program->query_callback(program->query_ctx, i), il_routine, il_bb);
        }

        for (DCLangBasicBlock *bb = il_routine->basic_blocks; bb; bb = bb->next) {
            if (bb->go_to_true) bb->go_to_true = il_resolve(il_routine->basic_blocks, bb->go_to_true);
            if (bb->go_to) bb->go_to = il_resolve(il_routine->basic_blocks, bb->go_to);
            else bb->go_to = bb->next;
        }

        /*for (DCLangBasicBlock *b = il_routine->basic_blocks; b; b = b->next) {*/
        /*    printf("bb:\n");*/
        /*    for (DCLangInstruction *i = b->instructions; i; i = i->next)*/
        /*        printf("%s %d\n", dc_lang_opcode_enum_str[i->opcode], i->immediate > 0x10000 ? i->variable->index : i->immediate);*/
        /*}*/

        /*for (DCLangBasicBlock *bb = il_routine->basic_blocks; bb; bb = bb->next) {*/
        /*    printf("bb @ %p (n_in_degrees=%d), (is_header=%d)\n", (void*)bb->native_start_va, bb->n_in_degrees, bb->is_header);*/
        /*    if (bb->go_to) printf("   | go_to %p\n", (void*)bb->go_to->native_start_va);*/
        /*    if (bb->go_to_true) printf("   | go_to_true %p\n", (void*)bb->go_to_true->native_start_va);*/
        /*}*/

        il_routine->cfg = dc_traverse(il_routine->basic_blocks);
        
        /*dc_convert_to_ssa(il_routine, nodes);*/

        /*printf("/*\n");*/
        /*for (DCControlNode *node = nodes; node; node = node->next) {*/
        /*    char prefix[8*4] = "";*/
        /*    char lprefix[8*4] = "";*/
        /*    for (int i = 0; i < node->level; i++) ((uint32_t*)prefix)[i] = (uint32_t)'    ';*/
        /*    for (int i = 0; i < node->level+1; i++) ((uint32_t*)lprefix)[i] = (uint32_t)'    ';*/
        /**/
        /*    printf(" * ");*/
        /*    switch (node->type) {*/
        /*    case CONTROL_NODE_BODY: printf("%sbody (%s): %p (next_in_level %p)\n", prefix, str_scope[node->scope], node->bb->native_start_va, node->next_in_level ? node->next_in_level->bb->native_start_va : 0); break;*/
        /*    case CONTROL_NODE_IF: printf("%sif (%s): %p (next_in_level %p)\n", prefix, str_scope[node->scope], node->bb->native_start_va, node->next_in_level ? node->next_in_level->bb->native_start_va : 0); break;*/
        /*    case CONTROL_NODE_IF_ELSE: printf("%sif-else (%s): %p (next_in_level %p)\n", prefix, str_scope[node->scope], node->bb->native_start_va, node->next_in_level ? node->next_in_level->bb->native_start_va : 0); break;*/
        /*    case CONTROL_NODE_WHILE: printf("%swhile (%s): %p (next_in_level %p)\n", prefix, str_scope[node->scope], node->bb->native_start_va, node->next_in_level ? node->next_in_level->bb->native_start_va : 0); break;*/
        /*    case CONTROL_NODE_INVALID: printf("%sinvalid (%s): %p (next_in_level %p)\n", prefix, str_scope[node->scope], node->bb->native_start_va, node->next_in_level ? node->next_in_level->bb->native_start_va : 0); break;*/
        /*    }*/
        /**/
        /*    for (DCLangInstruction *i = node->bb->instructions; i; i = i->next) {*/
        /*        if ((i->opcode >= DC_IL_JMP && i->opcode <= DC_IL_JS) || i->opcode == DC_IL_RET) {*/
        /*            printf(" * %s%-6s\n", lprefix, dc_lang_opcode_enum_str[i->opcode]);*/
        /*            continue;*/
        /*        }*/
        /**/
        /*        char s[8];*/
        /*        printf(" * %s%-6s i%-2d ", lprefix, dc_lang_opcode_enum_str[i->opcode], i->size);*/
        /*        switch (i->opcode) {*/
        /*        case DC_IL_LOAD_IMM: printf("%ld\n", i->immediate); break;*/
        /*        case DC_IL_LOAD_REG: */
        /*        /*case DC_IL_STORE: printf("%s\n", il_var_name(i->variable, s)); break;*/
        /*        default: puts(""); break;*/
        /*        }*/
        /*    }*/
        /*}*/
        /*printf("\n");*/

        /*
         * to-do: add validation checks to the CFG generation
         */
    }

    /*
     * set retvals
     */
    for (DCLangRoutine *il_routine = program->lang_routines; il_routine; il_routine = il_routine->next) {
        DCLangVariable *result = NULL;
        for (DCLangVariable *v = il_routine->variables; v; v = v->next)
            if (backend.operand_is_ret_val(&backend, v->native_operand)) {
                il_routine->retval = v;
                il_routine->retval_size = v->size;
                break;
            }
    }

    /*
     * post process call instructions with leading store instruction
     */
    for (DCLangRoutine *il_routine = program->lang_routines; il_routine; il_routine = il_routine->next) {
        for (DCLangBasicBlock *il_bb = il_routine->basic_blocks; il_bb; il_bb = il_bb->next) {
            for (DCLangInstruction *ins = il_bb->instructions; ins;) {
                DCLangInstruction *i0 = ins;
                DCLangInstruction *i1 = ins->next;

                if (i0 == NULL || i1 == NULL) break;
                if (i0->opcode != DC_IL_CALL || i1->opcode != DC_IL_STORE) { ins = i1; continue; }

                DCLangRoutine *resolved_routine = il_resolve_routine(program, i0->immediate);

                /*
                 * two scenarios:
                 *  1. retval is not found, so we can dispose of the store stub
                 *  2. retval is found, we should set the correct variable
                 */
                
                if (resolved_routine->retval == NULL) {
                    i0->next = i1->next;
                    free(i1);
                    ins = i0->next;
                    continue;
                }

                i1->variable = il_get_variable(backend, il_routine, resolved_routine->retval->native_operand, false);
                i1->size = i1->variable->size;
                ins = i1->next;
            }
        }
    }

    /*
     * optimizations
     */
    if (program->optimization_level != 0) {
        for (DCLangRoutine *il_routine = program->lang_routines; il_routine; il_routine = il_routine->next) {
            dc_optimizer_copy_propagation(il_routine->cfg, il_routine);
            dc_optimizer_simplify_shifts(il_routine);
            dc_optimizer_remove_dead_code(il_routine);
            dc_optimizer_remove_dead_common_code(il_routine);
            dc_optimizer_remove_dead_variables(backend, il_routine);
            /* dc_optimizer_remove_dead_code_v2(il_routine->cfg, il_routine); */
        }
    }
    
    for (DCLangRoutine *il_routine = program->lang_routines; il_routine; il_routine = il_routine->next)
        print_routine(program, formatter, backend, il_routine, il_routine->cfg, dst, n);

    return DC_ERROR_NONE;
}
