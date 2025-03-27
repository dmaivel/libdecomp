#ifndef LIBDECOMP_FORMATTER_H
#define LIBDECOMP_FORMATTER_H

#include "backend.h"
#include "libdecomp.h"

struct DCFormatterContext;

typedef struct DCFormatterImplementation {
    void(*fmt_function_header)(struct DCFormatterContext *ctx, char *dst, size_t n, DCLangRoutine *il_routine);
    void(*fmt_conditional_header)(struct DCFormatterContext *ctx, char *dst, size_t n, DCControlNodeType cond, char *expr_left, char *expr_right, char *op);
    void(*fmt_else_header)(struct DCFormatterContext *ctx, char *dst, size_t n);
    void(*fmt_header_epilogue)(struct DCFormatterContext *ctx, char *dst, size_t n);
    void(*fmt_memory_location)(struct DCFormatterContext *ctx, char *dst, size_t n, char *location_expr, int bitsize);
} DCFormatterImplementation;

typedef struct DCFormatterContext {
    int indent_repeat;
    char indent_char;

    char routine_prefix[16];
    char variable_prefix[16];
    char argument_prefix[16];
    char endline[8];

    /*
     * to-do: do this better, maybe `fmt_assignment`...
     * must take in 3 strings (%s): dst, src, newline
     */
    char assignment_format[16];
    
    /*
     * same issue as above
     * must take in 3 strings: left, op, right
     */
    char arithmetic_format[16];

    /*
     * hello look above please
     * must take in 2 strings: src, newline
     */
    char return_format[16];

    int n_indents;

    DCFormatterImplementation implementation;
} DCFormatterContext;

void DC_FormatAppend(char *dst, size_t n, char *fmt, ...);
void DC_FormatAppendRoutine(DCFormatterContext *ctx, char *dst, size_t n, DCLangRoutine *routine);
void DC_FormatAppendVariable(DCFormatterContext *ctx, char *dst, size_t n, DCLangVariable *variable);

void DC_FormatIndent(DCFormatterContext *ctx, char *dst, size_t n, int count);

#endif /* LIBDECOMP_FORMATTER_H */
