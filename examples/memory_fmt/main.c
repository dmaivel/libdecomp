#ifdef ZYDIS
#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_ZYDIS
#else
#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_CAPSTONE
#endif
#include <libdecomp/libdecomp.h>
#include <libdecomp/formatter/lang_c.h>
#include <libdecomp/formatter/lang_zig.h>
#include <libdecomp/formatter/lang_py.h>

#define BASE_ADDRESS 0x1000

#ifdef ZYDIS
static void *query(void *ctx, size_t index)
{
    ZydisDisassembledInstruction *i = ctx;
    return &i[index];
}
#else 
static void *query(void *ctx, size_t index)
{
    cs_insn *i = ctx;
    return &i[index];
}
#endif

int main()
{
    static const uint8_t data[] = {
#ifndef WRITE
        0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x40, 
        0x00, 0x8b, 0x00, 0x5d, 0xc3
#else
        0x55, 0x48, 0x89, 0xe5, 0xb8, 0x00, 0x00, 0x40, 
        0x00, 0x67, 0xc7, 0x00, 0x37, 0x13, 0x00, 0x00, 
        0x5d, 0xc3
#endif
    };

#ifdef ZYDIS
    ZydisDisassembledInstruction ins[64];
    size_t base_address = BASE_ADDRESS;
    int count = 0;
    size_t offset = 0;
    ZydisMachineMode mode = ZYDIS_MACHINE_MODE_LONG_64;

    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        mode,
        base_address,
        data + offset,
        sizeof(data) - offset,
        &ins[count]
    ))) {
        base_address += ins[count].info.length;
        offset += ins[count].info.length;
        count++;
    }

    DCProgram *program = DC_ProgramCreate();
    DC_ProgramSetImage(program, query, ins, count);

    DCDisassemblerBackend backend = DC_DisassemblerZydis(mode);
    DC_ProgramSetBackend(program, &backend);
#else 
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
#endif
    
    DCFormatterContext formatter = DC_FormatterLangC();
    DC_ProgramSetFormatter(program, &formatter);

    char buffer[1024];
    DC_ProgramDecompile(program, 
                        BASE_ADDRESS, 
                        data, sizeof(data),
                        buffer, sizeof(buffer));

    printf("%s\n", buffer);
    return 0;
}
