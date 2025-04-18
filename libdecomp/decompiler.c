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

static DCLangOpcodeEnum dc_eval(DCFormatterContext formatter, char *dst, size_t n, DCLangBasicBlock *il_bb, DCStackElement **stack, DCStackElement **last, int indents, char *cmp0, char *cmp1, bool out)
{
    char elem[BUFFER_DEFAULT_LENGTH], elem2[BUFFER_DEFAULT_LENGTH], elem3[BUFFER_DEFAULT_LENGTH];
    char op[3];

    DCLangOpcodeEnum jmp_op = -1;

    for (DCLangInstruction *i = il_bb->instructions; i; i = i->next) {
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

DCControlNode *dc_emitter(DCFormatterContext formatter, char *dst, size_t n, DCControlNode *node, DCStackElement **stack, DCStackElement **last) 
{
    if (node == NULL) return NULL;

    DCLangBasicBlock *il_bb = node->bb;
    
    char op[4];
    char cmp0[BUFFER_DEFAULT_LENGTH], cmp1[BUFFER_DEFAULT_LENGTH];

    DCLangOpcodeEnum jmp_op = dc_eval(formatter, dst, n, il_bb, stack, last, node->level + 1, cmp0, cmp1, node->type != CONTROL_NODE_WHILE);
    
    if (node->type == CONTROL_NODE_IF_ELSE) {
        il2strop(jmp_op, op);
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_conditional_header(&formatter, dst, n, node->type, cmp0, cmp1, op);
        
        DCControlNode *next_node = dc_emitter(formatter, dst, n, node->next, stack, last);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);

        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_else_header(&formatter, dst, n);

        dc_emitter(formatter, dst, n, next_node, stack, last);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);
        
        return dc_emitter(formatter, dst, n, node->next_in_level, stack, last);
    }
    else if (node->type == CONTROL_NODE_IF) {
        if (node->next->scope == CONTROL_NODE_SCOPE_FALSE)
            il2strop_opposite(jmp_op, op);
        else
            il2strop(jmp_op, op);

        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_conditional_header(&formatter, dst, n, node->type, cmp0, cmp1, op);
        
        dc_emitter(formatter, dst, n, node->next, stack, last);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);

        return dc_emitter(formatter, dst, n, node->next_in_level, stack, last);
    }
    else if (node->type == CONTROL_NODE_WHILE) {
        il2strop(jmp_op, op);

        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_conditional_header(&formatter, dst, n, node->type, cmp0, cmp1, op);
        
        dc_emitter(formatter, dst, n, node->next, stack, last);
        dc_eval(formatter, dst, n, il_bb, stack, last, node->level + 2, cmp0, cmp1, true);
        
        DC_FormatIndent(&formatter, dst, n, node->level + 1);
        formatter.implementation.fmt_header_epilogue(&formatter, dst, n);
        return dc_emitter(formatter, dst, n, node->next_in_level, stack, last);
    }
    else if (node->scope == CONTROL_NODE_SCOPE_NONE) {
        if (node->next_in_level) {
            if (node->next_in_level->parent == node->parent)
                dc_emitter(formatter, dst, n, node->next_in_level, stack, last);
        }
        else dc_emitter(formatter, dst, n, node->next_in_level, stack, last);
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

    for (DCLangBasicBlock *bb = routine->basic_blocks; bb; bb = bb->next) {
        for (DCLangInstruction *i = bb->instructions; i;) {
            switch (i->opcode) {
            /*case DC_IL_LOAD_REG:*/
            case DC_IL_STORE:
                if (!read[i->variable->index] && !backend.operand_is_ret_val(&backend, i->variable->native_operand)) {
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
        if (!read[i] && !backend.operand_is_ret_val(&backend, vars[i]->native_operand))
            dynarr_free_element((void**)&routine->variables, vars[i]);
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

bool operation_to_be_compared(DCLangInstruction *root[], int offset, int max, DCLangVariable *track)
{
    DCLangVariable *stack[16] = { NULL };
    int stack_offset = 0;
    for (int j = offset; j < max; j++) {
        DCLangInstruction *i = root[j];

        switch (i->opcode) {
        case DC_IL_LOAD_REG:
            stack[stack_offset++] = i->variable;
            break;
        case DC_IL_STORE:
            stack_offset--;
            break;
        case DC_IL_LOAD_IMM:
            stack[stack_offset++] = NULL;
            break;
        case DC_IL_ADD:
        case DC_IL_SUB:
        case DC_IL_AND:
        case DC_IL_OR:
        case DC_IL_XOR:
        case DC_IL_SHL:
        case DC_IL_SHR:
            stack[--stack_offset] = NULL;
            break;
        case DC_IL_CMP:
            for (int i = 0; i < stack_offset; i++)
                if (stack[i] == track) return true;
            stack_offset -= 2;
        default:
             break;
        }

        if (stack_offset == 0)
            return false;
    }

    return false;
}

void dc_optimizer_copy_propagation_safe(DCControlNode *root)
{
    for (DCControlNode *node = root; node; node = node->next) {
        for (DCLangInstruction *i = node->bb->instructions; i;) {
            DCLangInstruction *i0 = i;
            DCLangInstruction *i1 = i->next;

            if (i0->opcode != DC_IL_LOAD_REG || (i1->opcode != DC_IL_STORE && i1->opcode != DC_IL_RET)) {
                i = i1;
                continue;
            }

            DCLangVariable *src = i0->variable;
            DCLangVariable *dst = i1->variable;


            for (DCLangInstruction *k = i1->next; k; k = k->next) {
                if (k->opcode == DC_IL_STORE && (k->variable == src || k->variable == dst))
                    break;

                if (k->variable == dst)
                    k->variable = src;
            }

            i = i1;
        }
    }
}

void dc_optimizer_copy_propagation(DCControlNode *root)
{
    /*for (DCControlNode *node = root; node; node = node->next) {*/
    /*    for (DCLangInstruction *i0 = node->bb->instructions; i0 && i0->next;) {*/
    /*        DCLangInstruction *i1 = i0->next;*/
    /*        if (i0->opcode != DC_IL_LOAD_REG || (i1->opcode != DC_IL_STORE && i1->opcode != DC_IL_RET)) {*/
    /*            i0 = i1;*/
    /*            continue;*/
    /*        }*/
    /**/
    /*        DCLangVariable *src = i0->variable;*/
    /*        DCLangVariable *dst = i1->variable;*/
    /**/
    /*        for (DCLangInstruction *i = i1->next; i; i = i->next) {*/
    /**/
    /*        }*/
    /*    }*/
    /*}*/

    DCLangInstruction *instructions[256];

    int j = 0;
    for (DCControlNode *node = root; node; node = node->next) {
        if (node->type == CONTROL_NODE_WHILE) continue;
        for (DCLangInstruction* i = node->bb->instructions; i; i = i->next) {
            instructions[j++] = i;
        }
    }

    for (int i = 0; i < j - 1;) {
        DCLangInstruction *i0 = instructions[i];
        DCLangInstruction *i1 = instructions[i + 1];

        if (i0->opcode != DC_IL_LOAD_REG || (i1->opcode != DC_IL_STORE && i1->opcode != DC_IL_RET)) {
            i++;
            continue;
        }

        DCLangVariable *src = i0->variable;
        DCLangVariable *dst = i1->variable;

        for (int k = i + 2; k < j - 1; k++) {
            if (instructions[k]->opcode == DC_IL_STORE && (instructions[k]->variable == src || instructions[k]->variable == dst))
                break;

            if (instructions[k]->variable == dst)
                instructions[k]->variable = src;
        }

        i += 2;
    }

    /*for (DCControlNode *node = root; node; node = node->next) {*/
    /*    DCLangInstruction *root_instructions = node->bb->instructions;*/
    /*    if (root_instructions == NULL)*/
    /*        continue;*/
    /**/
    /*    for (DCLangInstruction *i0 = root_instructions; i0->next;) {*/
    /*        DCLangInstruction *i1 = i0->next;*/
    /**/
    /*        if (i0->opcode != DC_IL_LOAD_REG || i1->opcode != DC_IL_STORE) {*/
    /*            i0 = i1;*/
    /*            continue;*/
    /*        }*/
    /**/
    /*        DCLangVariable *src = i0->variable;*/
    /*        DCLangVariable *dst = i1->variable;*/
    /**/
    /*        bool broke = false;*/
    /*        for (DCLangInstruction *i = i1->next; i; i = i->next) {*/
    /*            if (i->opcode == DC_IL_STORE && (i->variable == src || i->variable == dst)) {*/
    /*                /*broke = true;*/
    /*                break;*/
    /*            }*/
    /**/
    /*            if (i->variable == dst)*/
    /*                i->variable = src;*/
    /*        }*/
    /**/
    /*        if (!broke) {*/
    /*            for (DCControlNode *n = node->next; n; n = n->next) {*/
    /*                if (broke) break;*/
    /*                /*if (n->type != CONTROL_NODE_BODY) break;*/
    /*                for (DCLangInstruction *i = n->bb->instructions; i; i = i->next) {*/
    /*                    if (i->opcode == DC_IL_STORE && (i->variable == src || i->variable == dst)) {*/
    /*                        /*broke = true;*/
    /*                        break;*/
    /*                    }*/
    /**/
    /*                    if (i->variable == dst)*/
    /*                        i->variable = src;*/
    /*                }*/
    /*            }*/
    /*        }*/
    /**/
    /*        printf("broke=%d\n", broke);*/
    /**/
    /*        i0 = i1;*/
    /*    }*/
    /*} */
}

static void print_routine(DCFormatterContext formatter, DCDisassemblerBackend backend, DCLangRoutine *il_routine, DCControlNode *nodes, char *dst, size_t n)
{
    DCLangVariable *result = NULL;
    for (DCLangVariable *v = il_routine->variables; v; v = v->next)
        if (backend.operand_is_ret_val(&backend, v->native_operand)) {
            il_routine->retval = v;
            break;
        }

    formatter.implementation.fmt_function_header(&formatter, dst, n, il_routine);

    DCStackElement *stack = NULL, *last = NULL;
    dc_emitter(formatter, dst, n, nodes, &stack, &last);

    formatter.implementation.fmt_header_epilogue(&formatter, dst, n);
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

    DCNativeRoutine *routine = calloc(1, sizeof(DCNativeRoutine));

    /*
     * to-do: add a function which splits the initial big block into routines:
     *    - one routine is formed at the starting address
     *    - call instructions imm (callees)
     *    - possibly after ret instructions, or if given an ABI hint like SYSV
     *      where we can detect prologues and epilogues
     */

    dc_native_basic_block_decompose(backend, routine, program);

    DCLangRoutine *il_routine = calloc(1, sizeof(DCLangRoutine));

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

    DCControlNode *nodes = dc_traverse(il_routine->basic_blocks);
    
    /*dc_convert_to_ssa(il_routine, nodes);*/

    dc_optimizer_copy_propagation_safe(nodes);
    dc_optimizer_simplify_shifts(il_routine);
    dc_optimizer_remove_dead_code(il_routine);
    dc_optimizer_remove_dead_common_code(il_routine);
    dc_optimizer_remove_dead_variables(backend, il_routine);

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
    print_routine(formatter, backend, il_routine, nodes, dst, n);
    program->lang_routines = il_routine;

    return DC_ERROR_NONE;
}
