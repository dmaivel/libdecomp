#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE
#include <libdecomp/libdecomp.h>
#include <libdecomp/formatter/lang_c.h>

#define BASE_ADDRESS 0x1000

static void *query(void *ctx, size_t index)
{
    cs_insn *i = ctx;
    return &i[index];
}

int main()
{
    static const uint8_t data[] = { 
        0x55, 0x48, 0x89, 0xe5, 0x89, 0x7d, 0xec, 0x8b, 
        0x45, 0xec, 0x89, 0x45, 0xfc, 0x8b, 0x45, 0xec, 
        0xf7, 0xd8, 0x89, 0x45, 0xf8, 0xeb, 0x14, 0x83, 
        0x7d, 0xfc, 0x00, 0x79, 0x06, 0x83, 0x45, 0xfc, 
        0x09, 0xeb, 0x04, 0x83, 0x45, 0xfc, 0x07, 0x83, 
        0x45, 0xf8, 0x01, 0x8b, 0x45, 0xf8, 0x3b, 0x45, 
        0xec, 0x7e, 0xe4, 0x8b, 0x45, 0xfc, 0x5d, 0xc3 
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
    
    DCFormatterContext formatter = DC_FormatterLangC();
    DC_ProgramSetFormatter(program, &formatter);

    char buffer[1024];
    DC_ProgramDecompile(program, 
                        buffer, 
                        sizeof(buffer));

    printf("%s", buffer);
    return 0;
}
