#ifndef LIBDECOMP_BACKEND_H
#define LIBDECOMP_BACKEND_H

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    DC_DISASM_OPERAND_INVALID = 0,
    DC_DISASM_OPERAND_IMM,
    DC_DISASM_OPERAND_REG,
    DC_DISASM_OPERAND_MEM
} DCDisassemblerOperandType;

struct DCDisassemblerBackend;

typedef struct DCDisassemblerBackend {
    void *backend_dependent_data;

    /**
    * @brief Return true if the provided instruction is an unconditional branch
    *
    * @param iobj Pointer to the instruction structure
    * @return status
    */
    bool(*instruction_is_jump)(struct DCDisassemblerBackend *self, void *iobj);

    /**
    * @brief Return true if the provided instruction is an conditional branch
    *
    * @param iobj Pointer to the instruction structure
    * @return status
    */
    bool(*instruction_is_jcc)(struct DCDisassemblerBackend *self, void *iobj);

    /**
    * @brief Return true if the provided instruction is a call
    *
    * @param iobj Pointer to the instruction structure
    */
    bool(*instruction_is_call)(struct DCDisassemblerBackend *self, void *iobj);

    /**
    * @brief Return true if the provided instruction is a ret
    *
    * @param iobj Pointer to the instruction structure
    */
    bool(*instruction_is_ret)(struct DCDisassemblerBackend *self, void *iobj);

    /**
    * @brief Return the address the branch instructions target
    *
    * @param iobj Pointer to the instruction structure
    */
    uint64_t(*instruction_get_jump_target)(struct DCDisassemblerBackend *self, void *iobj);
    
    /**
    * @brief Get the address of the next instruction if we didn't branch
    *
    * @param iobj Pointer to the instruction structure
    */
    uint64_t(*instruction_get_jump_passed)(struct DCDisassemblerBackend *self, void *iobj);

    /**
    * @brief Get base address of instruction
    *
    * @param iobj Pointer to the instruction structure
    * @return Address
    */
    uint64_t(*instruction_get_address)(struct DCDisassemblerBackend *self, void *iobj);

    /**
    * @brief Get pointer to operand located at user provided index
    *
    * @param iobj Pointer to the instruction structure
    * @param index Index of the operand
    * @return Pointer to operand structure if success, NULL if fail 
    */
    void*(*instruction_get_operand)(struct DCDisassemblerBackend *self, void *iobj, int index);

    /**
    * @brief Query operand type (convert backend specific type to DCDisassemblerOperandType)
    *
    * @param oobj Pointer to the operand structure
    * @return Type
    */
    DCDisassemblerOperandType(*operand_get_type)(struct DCDisassemblerBackend *self, void *oobj);
    
    /**
    * @brief Query the bitsize of the operand 
    *
    * @param oobj Pointer to the operand structure
    * @return Bitsize of operand
    */
    size_t(*operand_get_bitsize)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Get backend index of register
    *
    * @param oobj Pointer to the operand structure
    * @return Index of register
    */
    int(*operand_register_index)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Get backend largest enclosing index of register (e.g. AX->RAX, W0->X0)
    *
    * @param oobj Pointer to the operand structure
    * @return Index of register
    */
    int(*operand_register_largest_enclosing_index)(struct DCDisassemblerBackend *self, int index);

    /**
    * @brief Query the index of the base register 
    *
    * @param oobj Pointer to the operand structure
    * @retrun Index of the the base register
    */
    int(*operand_memory_base_register_index)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Query the displacement
    *
    * @param Pointer to the operand structure
    * @return Displacement
    */
    int64_t(*operand_memory_disp)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Determine if an operand would be referred to as a stack variable
    *
    * @param Pointer to the operand structure
    * @return True if the operand is considered a stack variable
    */
    bool(*operand_is_stack_var)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Determine if an operand would be considered the return value
    *
    * @param Pointer to the operand structure
    * @return True if the operand is considred the return value
    */
    bool(*operand_is_ret_val)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Query the immediate value of an operand
    *
    * @param oobj Pointer to the operand structure
    * @return Immediate
    */
    uint64_t(*operand_immediate_value)(struct DCDisassemblerBackend *self, void *oobj);

    /**
    * @brief Compare two operands
    *
    * @param oobj0 
    * @param oobj1
    * @return Returns true if two operands are equivalent, false otherwise
    */
    bool(*operand_cmp)(struct DCDisassemblerBackend *self, void *oobj0, void *oobj1);

    /**
    * @brief Lift instruction to decompiler IL
    *
    * @param iobj Pointer to the instruction structure
    * @param il_routine Pointer to IL routine, user should cast to DCLangRoutine
    * @param il_basic_block Pointer to IL basic block, user should cast to DCLangBasicBlock
    */
    void(*lift_instruction)(struct DCDisassemblerBackend *self, void *iobj, void *il_routine, void *il_basic_block); 
} DCDisassemblerBackend;

#endif /* LIBDECOMP_BACKEND_H */
