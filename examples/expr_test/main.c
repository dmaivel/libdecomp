#include <string.h>
#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE
#include <libdecomp/libdecomp.h>
#include <libdecomp/formatter/lang_expr.h>

#define BASE_ADDRESS 0x1000

static void *query(void *ctx, size_t index)
{
    cs_insn *i = ctx;
    return &i[index];
}

int main()
{
    static const uint8_t data[] = { 
        0xb8, 0x7b, 0x00, 0x00, 0x00, 0xb9, 0x41, 0x01, 
        0x00, 0x00, 0x01, 0xc8, 0xc3
    };

    csh handle;
    cs_insn *insn;
    size_t count;
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = CS_MODE_64;

    cs_open(arch, mode, &handle);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); 
    count = cs_disasm(handle, data, sizeof(data), BASE_ADDRESS, 0, &insn);

    DCProgram *program = DC_ProgramCreate();
    DC_ProgramSetImage(program, query, insn, count);

    DCDisassemblerBackend backend = DC_DisassemblerCapstone(arch, mode);
    DC_ProgramSetBackend(program, &backend);
    
    DCFormatterContext formatter = DC_FormatterLangExpr();
    DC_ProgramSetFormatter(program, &formatter);

    char buffer[1024];
    DC_ProgramDecompile(program, 
                        BASE_ADDRESS, 
                        data, sizeof(data),
                        buffer, sizeof(buffer));

    char *expected = "u32()[v0:u32,v1:u32]{v0=123,v1=321,v0=(v0+v1),__return__(v0)}";

    assert(strcmp(buffer, expected) == 0);
    printf("passed\n");
    return 0;
}
