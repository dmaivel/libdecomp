#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE
#include <libdecomp/libdecomp.h>
#include <libdecomp/formatter/lang_c.h>
#include <libdecomp/formatter/lang_zig.h>
#include <libdecomp/formatter/lang_py.h>
#include <libdecomp/formatter/lang_expr.h>

#include <string.h>
#include <ctype.h>

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define ARR_LEN(x) (sizeof(x) / sizeof(*x))

static const char *usage_message =
    "usage: decomp-cli input_path [-m arch] [-l lang] [-v variable_prefix] [-a argument_prefix] [-s subroutine_prefix] [-b base_addr] [-c]\n"
    "\n"
    "options:\n"
    "  input_path                 : path to input binary\n"
    "  -m [arm64, x86, x64]       : specify binary architecture (default: x64)\n"
    "  -l [c, zig, python, expr]  : specify output language (default: c)\n"
    "  -v [variable_prefix]       : specify variable prefix (default: var)\n"
    "  -a [argument_prefix]       : specify argument prefix (default: arg)\n"
    "  -s [subroutine_prefix]     : specify subroutine prefix (default: sub_)\n"
    "  -b [base_addr]             : specify base address (default: 0x1000)\n"            
    "  -c                         : enable colored output (default: false)";

static const char *hl_types[] = { "int8_t", "uint8_t", "int16_t", "uint16_t", "int32_t", "uint32_t",
                                  "int64_t", "uint64_t", "i8", "i16", "i32", "i64", "void"};
static uint32_t hl_types_h[ARR_LEN(hl_types)] = { -1 };

static const char *hl_keyws[] = {"for", "while", "if", "else", "return",
                                 "pub", "def",   "fn", "var",  "pub"};
static uint32_t hl_keyws_h[ARR_LEN(hl_keyws)] = { -1 };

/*
 * to-do: use gperf
 */
static uint32_t fnv1a(char *s)
{
    uint32_t x = 0x811c9dc5;
    while (*s) {
        x ^= *s++;
        x *= 0x01000193;
    }
    return x;
}

static bool is_type(char *s)
{
    if (hl_types_h[0] == -1) {
        for (int i = 0; i < ARR_LEN(hl_types); i++)
            hl_types_h[i] = fnv1a((char*)hl_types[i]);
    }
    
    for (int i = 0; i < ARR_LEN(hl_types); i++)
        if (fnv1a(s) == hl_types_h[i])
            return true;
    return false;
}

static bool is_keyword(char *s)
{
    if (hl_keyws_h[0] == -1) {
        for (int i = 0; i < ARR_LEN(hl_keyws); i++)
            hl_keyws_h[i] = fnv1a((char*)hl_keyws[i]);
    }

    for (int i = 0; i < ARR_LEN(hl_keyws); i++)
        if (fnv1a(s) == hl_keyws_h[i])
            return true;
    return false;
}

static void exit_with_usage()
{
    printf("%s\n", usage_message);
    exit(1);
}

static void *query(void *ctx, size_t index)
{
    cs_insn *i = ctx;
    return &i[index];
}

static bool is_pe(const uint8_t *buffer) 
{
    return buffer[0] == 'M' && buffer[1] == 'Z';
}

static bool is_elf(const uint8_t *buffer) 
{
    return buffer[0] == 0x7F && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F';
}

static bool is_seperator(char c)
{
    switch (c) {
    case ' ':
    case '-':
    case ';':
    case '(':
    case ')':
    case ':':
    case ',':
    case '\n':
        return true;
    default:
        return false;
    }
}

int main(int argc, char **argv)
{
    if (argc < 2)
        exit_with_usage();

    struct {
        char name[8];
        cs_arch arch;
        cs_mode mode;
    } supported_archs[] = {
        { /* .name = */ "arm64",
          /* .arch = */ CS_ARCH_ARM64,
          /* .mode = */ CS_MODE_ARM },
        { /* .name = */ "x86",
          /* .arch = */ CS_ARCH_X86,
          /* .mode = */ CS_MODE_32 },
        { /* .name = */ "x64",
          /* .arch = */ CS_ARCH_X86,
          /* .mode = */ CS_MODE_64 },
    };

    struct {
        char name[8];
        DCFormatterContext formatter;
    } supported_langs[] = {
        { /* .name = */      "c", 
          /* .formatter = */ DC_FormatterLangC() },
        { /* .name = */      "zig", 
          /* .formatter = */ DC_FormatterLangZig() },
        { /* .name = */      "python", 
          /* .formatter = */ DC_FormatterLangPython() },
        { /* .name = */      "expr", 
          /* .formatter = */ DC_FormatterLangExpr() },
    };

    DCFormatterContext *formatter = &supported_langs[0].formatter;
    char *input_path = NULL;
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = CS_MODE_64;

    bool colored = false;

    char *override_var = NULL;
    char *override_arg = NULL;
    char *override_sub = NULL;

    uint64_t base_address = 0x1000;
    
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') { 
            input_path = argv[i];
            continue;
        }

        bool good = false;
        switch (argv[i][1]) {
        case 'm':
            if (i + 1 >= argc)
                exit_with_usage();
            for (int j = 0; j < ARR_LEN(supported_archs); j++)
                if (strcmp(supported_archs[j].name, argv[i + 1]) == 0) {
                    arch = supported_archs[j].arch;
                    mode = supported_archs[j].mode;
                    good = true;
                    break;
                }
            if (!good)
                exit_with_usage();
            i++;
            break;
        case 'l':
            if (i + 1 >= argc)
                exit_with_usage();
            for (int j = 0; j < ARR_LEN(supported_langs); j++) {
                if (strcmp(supported_langs[j].name, argv[i + 1]) == 0) {
                    formatter = &supported_langs[j].formatter;
                    good = true;
                    break;
                }
            }
            if (!good)
                exit_with_usage();
            i++;
            break;
        case 'v':
            override_var = argv[i + 1];
            i++;
            break;
        case 'a':
            override_arg = argv[i + 1];
            i++;
            break;
        case 's':
            override_sub = argv[i + 1];
            i++;
            break;
        case 'b':
            if (i + 1 >= argc)
                exit_with_usage();
            sscanf(argv[i + 1], "%llx", &base_address);
            i++;
            break;
        case 'c':
            colored = true;
            break;
        default:
            exit_with_usage();
        }
    }

    if (input_path == NULL) {
        printf("error: no input file specified\n");
        exit_with_usage();
    }

    FILE *f = fopen(input_path, "rb");
    if (f == NULL) {
        printf("error: input file not found\n");
        exit_with_usage();
    }

    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *data = malloc(fsize);
    fread(data, 1, fsize, f);
    fclose(f);

    if (fsize > 4 && (is_pe(data) || is_elf(data))) {
        printf("error: binary is likely not a pure binary, executable formats not supported\n");
        exit_with_usage();
    }

    if (override_var)
        strncpy(formatter->variable_prefix, override_var, sizeof(formatter->variable_prefix));
    if (override_arg)
        strncpy(formatter->argument_prefix, override_arg, sizeof(formatter->argument_prefix));
    if (override_sub)
        strncpy(formatter->routine_prefix, override_sub, sizeof(formatter->routine_prefix));

    csh handle;
    cs_insn *insn;
    size_t count;

    cs_open(arch, mode, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); 
    count = cs_disasm(handle, data, fsize, base_address, 0, &insn);

    DCProgram *program = DC_ProgramCreate();
    DC_ProgramSetImage(program, query, insn, count);

    DCDisassemblerBackend backend = DC_DisassemblerCapstone(arch, mode);
    DC_ProgramSetBackend(program, &backend);
    DC_ProgramSetFormatter(program, formatter);

    char buffer[1024];
    DC_ProgramDecompile(program, 
                        buffer, 
                        sizeof(buffer));

    if (!colored) {
        printf("%s", buffer);
    }
    else {
        char *s = buffer;
        char *e = s;

        while (*s) {
            for (; *e && !is_seperator(*e); e++);

            char t = *e, del = 0;
            *e = 0;

            if (is_seperator(s[0]) && strlen(s) > 1) { del = s[0]; s++; }
            if (is_type(s)) {
                printf("%c" KGRN "%s" KNRM, del, s);
            }
            else if (is_keyword(s)) {
                printf("%c" KCYN "%s" KNRM, del, s);
            }
            else if (strstr(s, formatter->argument_prefix) || (strstr(s, formatter->variable_prefix) && strcmp(s, formatter->variable_prefix) != 0)) {
                printf("%c" KYEL "%s" KNRM, del, s);
            }
            else if (strncmp(s, formatter->routine_prefix, strlen(formatter->routine_prefix)) == 0) {
                printf("%c" KBLU "%s" KNRM, del, s);
            }
            else if (isdigit(s[0])) {
                printf("%c" KMAG "%s" KNRM, del, s);
            }
            else printf("%c%s", del, s);

            *e = t;
            s = e++;
        }
    }
    
    free(data);
    return 0;
}
