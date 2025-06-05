#ifndef LIBDECOMP_H
#define LIBDECOMP_H 

#include <stddef.h>
#include <stdbool.h>

#include "backend.h"

#define DC_MAKE_VERSION(maj, min) (maj << 8) | min

typedef void*(*DCProgramQueryInstructionCallback)(void *ctx, size_t index);

typedef enum DCError {
    DC_ERROR_NONE = 0,
    DC_ERROR_BAD_DISASM_INSTRUCTION,
    DC_ERROR_PROGRAM_MISSING_BACKEND,
    DC_ERROR_PROGRAM_MISSING_FORMATTER,
    DC_ERROR_MISSING_FMT_CALLBACK,
    DC_ERROR_MISSING_BACKEND_CALLBACK,
    DC_ERROR_MISSING_QUERY,
    DC_ERROR_BAD_CONTROL_FLOW,
} DCError;

typedef struct DCNativeBasicBlock {
    struct DCNativeBasicBlock *next;
    
    size_t query_begin;
    size_t query_end;

    uintptr_t start_va;
    uintptr_t end_va;
} DCNativeBasicBlock;

typedef struct DCNativeRoutine {
    struct DCNativeRoutine *next;
    
    DCNativeBasicBlock *basic_blocks;
    
    size_t query_begin;
    size_t query_end;

    uintptr_t start_va;
    uintptr_t end_va;
} DCNativeRoutine;

typedef enum DCLangOpcodeEnum {
    DC_IL_INVALID,
    DC_IL_LOAD_IMM,
    DC_IL_LOAD_REG,
    DC_IL_STORE,
    DC_IL_READ,
    DC_IL_WRITE,
    DC_IL_ADD,
    DC_IL_SUB,
    DC_IL_MUL,
    DC_IL_DIV,
    DC_IL_AND,
    DC_IL_OR,
    DC_IL_XOR,
    DC_IL_SHL,
    DC_IL_SHR,
    DC_IL_NEG,
    DC_IL_CMP,
    DC_IL_JMP,
    DC_IL_JZ,
    DC_IL_JNZ,
    DC_IL_JB,
    DC_IL_JNB,
    DC_IL_JBE,
    DC_IL_JNBE,
    DC_IL_JL,
    DC_IL_JLE,
    DC_IL_JNL,
    DC_IL_JNLE,
    DC_IL_JNS,
    DC_IL_JS,
    DC_IL_RET,
    DC_IL_CALL,
    DC_IL_PHI,
    DC_IL_MAX_ENUM
} DCLangOpcodeEnum;

static char dc_lang_opcode_enum_str[DC_IL_MAX_ENUM][12] = {
    "invalid",
    "load",
    "load",
    "store",
    "read",
    "write",
    "add",
    "sub",
    "mul",
    "div",
    "and",
    "or",
    "xor",
    "shl",
    "shr",
    "neg",
    "cmp",
    "jmp",
    "jz",
    "jnz",
    "jb",
    "jnb",
    "jbe",
    "jnbe",
    "jl",
    "jle",
    "jnl",
    "jnle",
    "jns",
    "js",
    "ret",
    "phi"
};

typedef enum {
    STOP_SUCCESS,
    STOP_NULL_BB,
    STOP_MERGE_POINT,
    STOP_ALREADY_VISITED
} DCTraverserStopReason;

typedef enum {
    CONTROL_NODE_INVALID,
    CONTROL_NODE_BODY,
    CONTROL_NODE_IF,
    CONTROL_NODE_WHILE,
    CONTROL_NODE_IF_ELSE,
} DCControlNodeType;

typedef enum {
    CONTROL_NODE_SCOPE_NONE,
    CONTROL_NODE_SCOPE_TRUE,
    CONTROL_NODE_SCOPE_FALSE
} DCControlNodeScope;

typedef struct DCLangVariable {
    struct DCLangVariable *next;

    int index;
    int size;
    bool is_param;
    void *native_operand;

    struct DCLangVariable *ssa_parent;
    struct DCLangVariable *ssa_list;
    struct DCLangVariable *ssa_last;
} DCLangVariable;

typedef struct DCLangInstruction {
    struct DCLangInstruction *next;

    DCLangOpcodeEnum opcode;
    size_t size;
    union {
        uint64_t immediate;
        DCLangVariable *variable;
    };
} DCLangInstruction;

typedef struct DCLangBasicBlock {
    struct DCLangBasicBlock *next;

    uintptr_t native_start_va;
    uintptr_t native_end_va;

    DCLangInstruction *instructions;
    struct DCLangBasicBlock *go_to;
    struct DCLangBasicBlock *go_to_true;
} DCLangBasicBlock;

typedef struct DCControlNode {
    struct DCControlNode *next;
    struct DCControlNode *next_in_level;
    struct DCControlNode *parent;
    
    int level;
    DCControlNodeType type;
    DCControlNodeScope scope;

    DCLangBasicBlock *bb;

    DCLangVariable **ssa_last_array;
} DCControlNode;

typedef struct DCLangRoutine {
    struct DCLangRoutine *next;

    DCLangBasicBlock *basic_blocks;
    DCLangVariable *variables;

    DCLangVariable *retval;
    int retval_size; // had to add this in the event retval is optimized out

    DCControlNode *cfg;

    int n_params;
} DCLangRoutine;

typedef enum DCProgramSectionType {
    DC_PROGRAM_SECTION_EMPTY = 0,
    DC_PROGRAM_SECTION_CODE,
    DC_PROGRAM_SECTION_DATA,
    DC_PROGRAM_SECTION_SYMBOLS
} DCProgramSectionType;

typedef struct DCProgramSection {
    DCProgramSectionType type;

    union {
        struct {

        } code;
        struct {

        } data;
        struct {

        } symbols;
    };
} DCProgramSection;

typedef struct DCProgram {
    DCDisassemblerBackend *disasm_backend;
    struct DCFormatterContext *formatter;

    DCProgramQueryInstructionCallback query_callback;
    void *query_ctx;
    size_t query_len;

    DCNativeBasicBlock *initial_image;

    DCNativeRoutine *native_routines;
    DCLangRoutine *lang_routines;
    bool bad;

    int optimization_level;
} DCProgram;

void add_ins(DCLangInstruction **root, DCLangInstruction ins);
void il_load(DCDisassemblerBackend backend, DCLangRoutine *routine, DCLangBasicBlock *bb, void *operand);
void il_store(DCDisassemblerBackend backend, DCLangRoutine *routine, DCLangBasicBlock *bb, void *operand);

#ifdef LIBDECOMP_ENABLE_BUILTIN_BACKEND_ZYDIS
#include "backend/zydis.h"
#endif

#ifdef LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE
#include "backend/capstone.h"
#endif

struct DCFormatterContext;

/**
* @brief Get the library version major and minor
*
* @param major Optional pointer to retreive major version
* @param minor Optional pointer to retreive minor version
*
* @return Version encoded as (major << 8) | minor
*/
int DC_Version(int *major, int *minor);

/**
* @brief Create a decompilation state
*
* @return Allocated state; to be freed by user using `free`
*/
DCProgram *DC_ProgramCreate();

/**
* @brief Set the program image
*
* @param program Program
* @param query_callback Query callback, returns pointer to instruction at a specified index
* @param ctx User context, may contain instruction array or any structure for query_callback to handle
* @param count Number of instructions in image
*/
void DC_ProgramSetImage(DCProgram *program, 
                        DCProgramQueryInstructionCallback query_callback, 
                        void *ctx, 
                        size_t count);

/**
* @brief Set disassembler backend
*
* @param program Program
* @param backend Disassembler interface
*/
void DC_ProgramSetBackend(DCProgram *program,
                          DCDisassemblerBackend *backend);

/**
* @brief Set output formatter
*
* @param program Program
* @param formatter Output formatter
*/
void DC_ProgramSetFormatter(DCProgram *program,
                            struct DCFormatterContext *formatter);

/**
 * @brief Set optimization level (may be either 0 or 1)
 *        TODO: Replace with list of optimization functions
 *
 * @param program Program
 * @param level Optimization level */
void DC_ProgramSetOptimizationLevel(DCProgram *program,
                                    int level);

/**
* @brief Decompile `program` as if it were loaded at `base_address`
*
* @param program Program
* @param dst Destination buffer
* @param n Size of destination buffer
*
* @return DCError
*/
DCError DC_ProgramDecompile(DCProgram *program, 
                            char *dst,
                            const size_t n);

#endif /* LIBDECOMP_H */
