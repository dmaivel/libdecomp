#define LIBDECOMP_ENABLE_BUILTIN_BACKEND_ZYDIS
#include <libdecomp/libdecomp.h>
#include <libdecomp/formatter/lang_c.h>

#define BASE_ADDRESS 0x1000

static void *query(void *ctx, size_t index)
{
    ZydisDisassembledInstruction *i = ctx;
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
    
    DCFormatterContext formatter = DC_FormatterLangC();
    DC_ProgramSetFormatter(program, &formatter);

    char buffer[1024];
    DC_ProgramDecompile(program, 
                        buffer, 
                        sizeof(buffer));

    printf("%s", buffer);
    return 0;
}
