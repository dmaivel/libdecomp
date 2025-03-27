#include <libdecomp/formatter.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

void strcat_safe(char *dst, const char *src, size_t n) 
{
    strncat(dst, src, n - strlen(dst) - 1);
}

void DC_FormatAppend(char *dst, size_t n, char *fmt, ...)
{
    /*
     * to-do: don't hardcode
     */ 
    char buffer[4096];

    va_list args;
    va_start(args, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    strcat_safe(dst, buffer, n);
}

void DC_FormatAppendRoutine(DCFormatterContext *ctx, char *dst, size_t n, DCLangRoutine *routine)
{
    DC_FormatAppend(dst, n, "%s%lx", ctx->routine_prefix, routine->basic_blocks[0].native_start_va);
}

void DC_FormatAppendVariable(DCFormatterContext *ctx, char *dst, size_t n, DCLangVariable *variable)
{
    /*if (v->ssa_parent) sprintf(dst, "%s%d_%d", v->is_param ? "a" : "v", v->ssa_parent->index, v->index);*/
    DC_FormatAppend(dst, n, "%s%d", variable->is_param ? ctx->argument_prefix : ctx->variable_prefix, variable->index);
}

void DC_FormatIndent(DCFormatterContext *ctx, char *dst, size_t n, int count)
{
    const char s[] = { ctx->indent_char, '\0' };

    for (int i = 0; i < count; i++)
        for (int j = 0; j < ctx->indent_repeat; j++)
            strcat_safe(dst, s, n);
}
