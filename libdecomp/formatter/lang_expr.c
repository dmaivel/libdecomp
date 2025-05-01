#include <libdecomp/formatter/lang_expr.h>
#include <string.h>

static void fmt_function_header(DCFormatterContext *ctx, char *dst, size_t n, DCLangRoutine *il_routine)
{
    if (il_routine->retval_size) DC_FormatAppend(dst, n, "u%d@%lx(", il_routine->retval_size, il_routine->basic_blocks[0].native_start_va);
    else DC_FormatAppend(dst, n, "none@%lx(", il_routine->basic_blocks[0].native_start_va);

    int j = 0;
    for (DCLangVariable *v = il_routine->variables; v; v = v->next)
        if (v->is_param) {
            DC_FormatAppendVariable(ctx, dst, n, v);
            DC_FormatAppend(dst, n, ":u%d", v->size);
            DC_FormatAppend(dst, n, "%s", ++j != il_routine->n_params ? "," : "");
        }
    DC_FormatAppend(dst, n, ")[");

    /*
     * to-do: this should probably be a variable in il_routine?
     */
    size_t n_locals = 0;
    for (DCLangVariable *v = il_routine->variables; v; v = v->next) n_locals++;
    /*n_locals -= il_routine->n_params;*/

    for (DCLangVariable *v = il_routine->variables; v; v = v->next)
        if (!v->is_param) {
            DC_FormatAppendVariable(ctx, dst, n, v);
            DC_FormatAppend(dst, n, ":u%d", v->size);
            DC_FormatAppend(dst, n, "%s", ++j != n_locals ? "," : "");
        }

    DC_FormatAppend(dst, n, "]{");
}

static void fmt_conditional_header(DCFormatterContext *ctx, char *dst, size_t n, DCControlNodeType cond, char *expr_left, char *expr_right, char *op)
{
    switch (cond) {
    case CONTROL_NODE_IF:
    case CONTROL_NODE_IF_ELSE:
        DC_FormatAppend(dst, n, "if(%s%s%s){", expr_left, op, expr_right);
        break;
    case CONTROL_NODE_WHILE:
        DC_FormatAppend(dst, n, "while(%s%s%s){", expr_left, op, expr_right);
        break;
    default:
        break;
    }  
}

static void fmt_else_header(DCFormatterContext *ctx, char *dst, size_t n)
{
    DC_FormatAppend(dst, n, "else{");
}

static void fmt_header_epilogue(DCFormatterContext *ctx, char *dst, size_t n)
{
    /*
     * to-do: maybe create an API
     * maybe DC_FormatReplaceCurrentChar()
     */
    char c = dst[strlen(dst) - 1];
    if (c == ',') dst[strlen(dst) - 1] = '}';
    else DC_FormatAppend(dst, n, "}");
}

static void fmt_memory_location(DCFormatterContext *ctx, char *dst, size_t n, char *location_expr, int bitsize)
{
    DC_FormatAppend(dst, n, "*(u%d*)%s", bitsize, location_expr);
}

DCFormatterContext DC_FormatterLangExpr()
{
    return (DCFormatterContext){
        .argument_prefix = "v",
        .routine_prefix = "",
        .variable_prefix = "v",
        .indent_char = ' ',
        .indent_repeat = 0,
        .endline = ",",
        .assignment_format = "%s=%s%s",
        .arithmetic_format = "(%s%s%s)",
        .return_format = "__return__(%s)%s",
        .implementation = {
            .fmt_function_header = fmt_function_header,
            .fmt_conditional_header = fmt_conditional_header,
            .fmt_else_header = fmt_else_header,
            .fmt_header_epilogue = fmt_header_epilogue,
            .fmt_memory_location = fmt_memory_location
        }
    };
}
