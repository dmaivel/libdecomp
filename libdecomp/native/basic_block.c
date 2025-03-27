#include "basic_block.h"
#include "../visitor.h"
#include "../dynarr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int qsort_cmp(const void *a, const void *b)
{
    uint64_t x = *(uint64_t*)a;
    uint64_t y = *(uint64_t*)b;
    return (x > y) - (x < y);
}

DCNativeBasicBlock *dc_native_routine_create_bb(DCNativeRoutine *routine,
                                                DCNativeBasicBlock data)
{
    DCNativeBasicBlock *bb = dynarr_alloc((void**)&routine->basic_blocks, 
                                           sizeof(DCNativeBasicBlock));
    
    memcpy(bb, &data, sizeof(DCNativeBasicBlock));
    bb->next = NULL;
    return bb;
}

DCNativeBasicBlock *dc_native_basic_block_decompose(DCDisassemblerBackend backend,
                                                    DCNativeRoutine *routine,
                                                    DCProgram *program)
{
    DCVisitor *visit = dc_visitor_create(128);
    uintptr_t start_va = -1;
    uintptr_t end_va = 0;
    for (size_t i = 0; i < program->query_len; i++) {
        void *ins = program->query_callback(program->query_ctx, i);
        end_va = backend.instruction_get_address(&backend, ins);
        if (start_va == -1) start_va = end_va;

        if (!backend.instruction_is_jump(&backend, ins))
            continue;

        dc_visitor_add(visit, backend.instruction_get_jump_target(&backend, ins));
        if (backend.instruction_is_jcc(&backend, ins))
            dc_visitor_add(visit, backend.instruction_get_jump_passed(&backend, ins));
    }

    dc_visitor_add(visit, end_va);

    uint64_t *addresses = dc_visitor_get_compressed(visit);
    qsort(addresses, visit->count, sizeof(uint64_t), qsort_cmp);

    DCNativeBasicBlock *current = dc_native_routine_create_bb(routine, (DCNativeBasicBlock){
        .start_va = start_va
    });

    size_t last_instruction_idx = 0;
    for (int i = 0; i < visit->count; i++) {
        uint64_t end_address = addresses[i]; 

        current->query_begin = last_instruction_idx;
        current->end_va = end_address;
        for (; last_instruction_idx < program->query_len; last_instruction_idx++) {
            void *ins = program->query_callback(program->query_ctx, last_instruction_idx);
            current->query_end = last_instruction_idx;
            if (backend.instruction_get_address(&backend, ins) >= end_address)
                break;
        }

        if (!(i+1<visit->count)) current->query_end++;

        current = dc_native_routine_create_bb(routine, (DCNativeBasicBlock){
            .start_va = end_address
        });
    }

    dynarr_free_element((void**)&routine->basic_blocks, current);
    free(addresses);
    free(visit);
    return routine->basic_blocks;
}
