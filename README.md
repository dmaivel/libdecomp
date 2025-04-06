<img align="right" width="15%" src="media/decomp.svg">

# libdecomp ![license](https://img.shields.io/badge/license-MIT-blue)

Library for decompiling multi-architecture bytecode into source code. 

## Features

- Pluggable disassembler backend; `Zydis`, `capstone` integration supported out of the box
- X86, X86-64, ARM64 support out of the box
- Optimizing compiler
- Custom formatter API
  - `C`, `Zig`, `python` formatters supported out the box

# Getting started

## Dependencies

`libdecomp` has no direct dependencies (except for the standard library). It relies on the user to supply a backend. If you are building the examples, `CMake` is capable of fetching both if they aren't present system-wide.

| Name | Version | Required | Notes |
| ---- | ------- | - | - |
| [CMake](https://cmake.org/) | 3.25+ | Yes |  |
| [Zydis](https://github.com/zyantific/zydis) | 4.1.1+ | No | Required if building `examples/`, or using Zydis backend |
| [capstone](https://github.com/capstone-engine/capstone) | 5.0.6+ | No | Required if building `examples/`, or using capstone backend | 

## Building

```bash
git clone https://github.com/dmaivel/libdecomp.git
cd libdecomp
cmake -B build
cmake --build build --config Release
```

#### Installation 

```bash
cd build 
make install
```

### Build options

These build options can either be specified during configuration or via `ccmake`:

| Option | Default | Description |
| - | - | - |
| `LIBDECOMP_BUILD_EXAMPLES` | `OFF` | Build the programs located in `examples/`
| `LIBDECOMP_BUILD_SHARED_LIB` | `OFF` | Build `libdecomp` as a shared library 

# Usage

For usage, take a look at the example applications and the public headers (`include/libdecomp/...`).

### Quick example

```c 
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

    printf("%s\n", buffer);
    return 0;
}
```

Upon execution, this code will print out:
```c 
int32_t sub_1000(int32_t arg0)
{
    int32_t var1;
    int32_t var2;
    int32_t var3;
    int32_t var4;

    var1 = arg0;
    var3 = arg0;
    var2 = -arg0;
    var4 = var2;
    while (var4 <= var1) {
        if (var3 >= 0) {
            var3 = (var3 + 7);
        }
        else {
            var3 = (var3 + 9);
        }
        var4 = (var4 + 1);
        var2 = var4;
    }
    var2 = var3;
    return var3;
}
```

If we were to replace `DC_FormatterLangC()` with `DC_FormatterLangZig()`, the output becomes:
```zig
pub fn sub_1000(arg0: i32) i32 {
    var var1: i32 = undefined;
    var var2: i32 = undefined;
    var var3: i32 = undefined;
    var var4: i32 = undefined;

    var1 = arg0;
    var3 = arg0;
    var2 = -arg0;
    var4 = var2;
    while (var4 <= var1) {
        if (var3 >= 0) {
            var3 = (var3 + 7);
        }
        else {
            var3 = (var3 + 9);
        }
        var4 = (var4 + 1);
        var2 = var4;
    }
    var2 = var3;
    return var3;
}
```

With `DC_FormatterLangPython`:
```python 
def sub_1000(arg0):
    var1 = None
    var2 = None
    var3 = None
    var4 = None

    var1 = arg0
    var3 = arg0
    var2 = -arg0
    var4 = var2
    while var4 <= var1:
        if var3 >= 0:
            var3 = (var3 + 7)

        else:
            var3 = (var3 + 9)

        var4 = (var4 + 1)
        var2 = var4

    var2 = var3
    return var3
```
