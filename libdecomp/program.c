#include <libdecomp/libdecomp.h>
#include <stdlib.h>

DCProgram *DC_ProgramCreate()
{
    DCProgram *program = calloc(1, sizeof(DCProgram));
    program->initial_image = calloc(1, sizeof(DCNativeBasicBlock));
    program->optimization_level = 1; // optimize by default, TODO revist

    return program;
}

void DC_ProgramSetImage(DCProgram *program,
                        DCProgramQueryInstructionCallback query_callback,
                        void *ctx,
                        size_t count)
{
    program->query_callback = query_callback;
    program->query_ctx = ctx;
    program->query_len = count;
}

void DC_ProgramSetBackend(DCProgram *program,
                          DCDisassemblerBackend *backend)
{
    program->disasm_backend = backend;
}

void DC_ProgramSetFormatter(DCProgram *program,
                            struct DCFormatterContext *formatter)
{
    program->formatter = formatter;
}

void DC_ProgramSetOptimizationLevel(DCProgram *program,
                                    int level)
{
    // TODO error check?
    // TODO replace with list of optimization functions
    program->optimization_level = level;
}
