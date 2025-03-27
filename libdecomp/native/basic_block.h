#ifndef NATIVE_BASIC_BLOCK_H
#define NATIVE_BASIC_BLOCK_H

#include <libdecomp/libdecomp.h>

DCNativeBasicBlock *dc_native_routine_create_bb(DCNativeRoutine *routine,
                                                DCNativeBasicBlock data);

DCNativeBasicBlock *dc_native_basic_block_decompose(DCDisassemblerBackend backend, 
                                                    DCNativeRoutine *routine,
                                                    DCProgram *program);

#endif /* NATIVE_BASIC_BLOCK_H */
