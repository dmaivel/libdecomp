#include <libdecomp/formatter/lang_c.h>
#include <string.h>

static void fmt_function_header(DCFormatterContext *ctx, char *dst, size_t n, DCLangRoutine *il_routine)
{
    /*
     * seperate functions if multiple are emitted
     */
    if (strlen(dst))
        DC_FormatAppend(dst, n, "\n");

    if (il_routine->retval_size) DC_FormatAppend(dst, n, "int%d_t ", il_routine->retval_size);
    else DC_FormatAppend(dst, n, "void ");
    DC_FormatAppendRoutine(ctx, dst, n, il_routine);
    DC_FormatAppend(dst, n, "(");

    int j = 0;
    for (DCLangVariable *v = il_routine->variables; v; v = v->next)
        if (v->is_param) {
            DC_FormatAppend(dst, n, "int%d_t ", v->size);
            DC_FormatAppendVariable(ctx, dst, n, v);
            DC_FormatAppend(dst, n, "%s", ++j != il_routine->n_params ? ", " : "");
        }
    DC_FormatAppend(dst, n, ")\n{\n");

    for (DCLangVariable *v = il_routine->variables; v; v = v->next)
        if (!v->is_param) {
            DC_FormatIndent(ctx, dst, n, 1);
            DC_FormatAppend(dst, n, "int%d_t ", v->size);
            DC_FormatAppendVariable(ctx, dst, n, v);
            DC_FormatAppend(dst, n, ";\n");
        }
    
    DC_FormatAppend(dst, n, "\n");
}

static void fmt_conditional_header(DCFormatterContext *ctx, char *dst, size_t n, DCControlNodeType cond, char *expr_left, char *expr_right, char *op)
{
    switch (cond) {
    case CONTROL_NODE_IF:
    case CONTROL_NODE_IF_ELSE:
        DC_FormatAppend(dst, n, "if (%s %s %s) {\n", expr_left, op, expr_right);
        break;
    case CONTROL_NODE_WHILE:
        DC_FormatAppend(dst, n, "while (%s %s %s) {\n", expr_left, op, expr_right);
        break;
    default:
        break;
    }  
}

static void fmt_else_header(DCFormatterContext *ctx, char *dst, size_t n)
{
    DC_FormatAppend(dst, n, "else {\n");
}

static void fmt_header_epilogue(DCFormatterContext *ctx, char *dst, size_t n)
{
    DC_FormatAppend(dst, n, "}\n");
}

static void fmt_memory_location(DCFormatterContext *ctx, char *dst, size_t n, char *location_expr, int bitsize)
{
    DC_FormatAppend(dst, n, "*(int%d_t*)%s", bitsize, location_expr);
}

DCFormatterContext DC_FormatterLangC()
{
    return (DCFormatterContext){
        .argument_prefix = "arg",
        .routine_prefix = "sub_",
        .variable_prefix = "var",
        .indent_char = ' ',
        .indent_repeat = 4,
        .endline = ";\n",
        .assignment_format = "%s = %s%s",
        .arithmetic_format = "(%s %s %s)",
        .return_format = "return %s%s",
        .implementation = {
            .fmt_function_header = fmt_function_header,
            .fmt_conditional_header = fmt_conditional_header,
            .fmt_else_header = fmt_else_header,
            .fmt_header_epilogue = fmt_header_epilogue,
            .fmt_memory_location = fmt_memory_location
        }
    };
}
