#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE
#include <libdecomp/libdecomp.h>
#include <libdecomp/formatter/lang_c.h>
#include <libdecomp/formatter/lang_zig.h>
#include <libdecomp/formatter/lang_py.h>
#include <libdecomp/formatter/lang_expr.h>

#include <string.h>

#define BASE_ADDRESS 0x1000

static const char *usage_message =
    "usage: decomp-cli input_path [-m arch] [-l lang]\n"
    "\n"
    "options:\n"
    "  input_path                 : path to input binary\n"
    "  -m [arm64, x86, x64]       : specify binary architecture (default: x64)\n"
    "  -l [c, zig, python, expr]  : specify output language (default: c)";

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
            for (int j = 0; j < sizeof(supported_archs) / sizeof(*supported_archs); j++)
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
            for (int j = 0; j < sizeof(supported_langs) / sizeof(*supported_langs); j++) {
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

    csh handle;
    cs_insn *insn;
    size_t count;

    cs_open(arch, mode, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); 
    count = cs_disasm(handle, data, fsize, BASE_ADDRESS, 0, &insn);

    DCProgram *program = DC_ProgramCreate();
    DC_ProgramSetImage(program, query, insn, count);

    DCDisassemblerBackend backend = DC_DisassemblerCapstone(arch, mode);
    DC_ProgramSetBackend(program, &backend);
    DC_ProgramSetFormatter(program, formatter);

    char buffer[1024];
    DC_ProgramDecompile(program, 
                        BASE_ADDRESS, 
                        data, sizeof(data),
                        buffer, sizeof(buffer));

    printf("%s", buffer);
    free(data);
    return 0;
}
