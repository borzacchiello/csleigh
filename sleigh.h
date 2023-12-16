#ifndef SLEIGH_H
#define SLEIGH_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

typedef enum sleigh_arch_t {
    SLEIGH_ARCH_INVALID = 0,
    SLEIGH_ARCH_X86_64  = 1,
    SLEIGH_ARCH_X86     = 2,
} sleigh_arch_t;

typedef enum sleigh_processor_t {
    SLEIGH_PROC_INVALID     = 0,
    SLEIGH_PROC_X86_64      = 1,
    SLEIGH_PROC_X86_16      = 2,
    SLEIGH_PROC_X86_16_REAL = 3,
    SLEIGH_PROC_X86         = 4,
} sleigh_processor_t;

#define OPS_X                                                                  \
    INV_OP(0, INVALID, "Invalid")                                              \
    DEC_OP(1, COPY, "Copy one operand to another")                             \
    DEC_OP(2, LOAD, "Load from a pointer into a specified address space")      \
    DEC_OP(3, STORE, "Store at a pointer into a specified address space")      \
    DEC_OP(4, BRANCH, "Always branch")                                         \
    DEC_OP(5, CBRANCH, "Conditional branch")                                   \
    DEC_OP(6, BRANCHIND, "Indirect branch (jumptable)")                        \
    DEC_OP(7, CALL, "Call to an absolute address")                             \
    DEC_OP(8, CALLIND, "Call through an indirect address")                     \
    DEC_OP(9, CALLOTHER, "User-defined operation")                             \
    DEC_OP(10, RETURN, "Return from subroutine")                               \
    DEC_OP(11, INT_EQUAL, "Integer comparison, equality (==)")                 \
    DEC_OP(12, INT_NOTEQUAL, "Integer comparison, in-equality (!=)")           \
    DEC_OP(13, INT_SLESS, "Integer comparison, signed less-than (<)")          \
    DEC_OP(14, INT_SLESSEQUAL,                                                 \
           "Integer comparison, signed less-than-or-equal (<=)")               \
    DEC_OP(15, INT_LESS, "Integer comparison, unsigned less-than (<)")         \
    DEC_OP(16, INT_LESSEQUAL,                                                  \
           "Integer comparison, unsigned less-than-or-equal (<=)")             \
    DEC_OP(17, INT_ZEXT, "Zero extension")                                     \
    DEC_OP(18, INT_SEXT, "Sign extension")                                     \
    DEC_OP(19, INT_ADD, "Addition, signed or unsigned (+)")                    \
    DEC_OP(20, INT_SUB, "Subtraction, signed or unsigned (-)")                 \
    DEC_OP(21, INT_CARRY, "Test for unsigned carry")                           \
    DEC_OP(22, INT_SCARRY, "Test for signed carry")                            \
    DEC_OP(23, INT_SBORROW, "Test for signed borrow")                          \
    DEC_OP(24, INT_2COMP, "Twos complement")                                   \
    DEC_OP(25, INT_NEGATE, "Logical/bitwise negation (~)")                     \
    DEC_OP(26, INT_XOR, "Logical/bitwise exclusive-or (^)")                    \
    DEC_OP(27, INT_AND, "Logical/bitwise and (&)")                             \
    DEC_OP(28, INT_OR, "Logical/bitwise or (|)")                               \
    DEC_OP(29, INT_LEFT, "Left shift (<<)")                                    \
    DEC_OP(30, INT_RIGHT, "Right shift, logical (>>)")                         \
    DEC_OP(31, INT_SRIGHT, "Right shift, arithmetic (>>)")                     \
    DEC_OP(32, INT_MULT, "Integer multiplication, signed and unsigned (*)")    \
    DEC_OP(33, INT_DIV, "Integer division, unsigned (/)")                      \
    DEC_OP(34, INT_SDIV, "Integer division, signed (/)")                       \
    DEC_OP(35, INT_REM, "Remainder/modulo, unsigned (%)")                      \
    DEC_OP(36, INT_SREM, "Remainder/modulo, signed (%)")                       \
    DEC_OP(37, BOOL_NEGATE, "Boolean negate (!)")                              \
    DEC_OP(38, BOOL_XOR, "Boolean exclusive-or (^^)")                          \
    DEC_OP(39, BOOL_AND, "Boolean and (&&)")                                   \
    DEC_OP(40, BOOL_OR, "Boolean or (||)")                                     \
    DEC_OP(41, FLOAT_EQUAL, "Floating-point comparison, equality (==)")        \
    DEC_OP(42, FLOAT_NOTEQUAL, "Floating-point comparison, in-equality (!=)")  \
    DEC_OP(43, FLOAT_LESS, "Floating-point comparison, less-than (<)")         \
    DEC_OP(44, FLOAT_LESSEQUAL,                                                \
           "Floating-point comparison, less-than-or-equal (<=)")               \
    INV_OP(45, INVALID, "Invalid")                                             \
    DEC_OP(46, FLOAT_NAN, "Not-a-number test (NaN)")                           \
    DEC_OP(47, FLOAT_ADD, "Floating-point addition (+)")                       \
    DEC_OP(48, FLOAT_DIV, "Floating-point division (/)")                       \
    DEC_OP(49, FLOAT_MULT, "Floating-point multiplication (*)")                \
    DEC_OP(50, FLOAT_SUB, "Floating-point subtraction (-)")                    \
    DEC_OP(51, FLOAT_NEG, "Floating-point negation (-)")                       \
    DEC_OP(52, FLOAT_ABS, "Floating-point absolute value (abs)")               \
    DEC_OP(53, FLOAT_SQRT, "Floating-point square root (sqrt)")                \
    DEC_OP(54, FLOAT_INT2FLOAT, "Convert an integer to a floating-point")      \
    DEC_OP(55, FLOAT_FLOAT2FLOAT,                                              \
           "Convert between different floating-point sizes")                   \
    DEC_OP(56, FLOAT_TRUNC, "Round towards zero")                              \
    DEC_OP(57, FLOAT_CEIL, "Round towards +infinity")                          \
    DEC_OP(58, FLOAT_FLOOR, "Round towards -infinity")                         \
    DEC_OP(59, FLOAT_ROUND, "Round towards nearest")                           \
    DEC_OP(60, MULTIEQUAL, "Phi-node operator")                                \
    DEC_OP(61, INDIRECT, "Copy with an indirect effect")                       \
    DEC_OP(62, PIECE, "Concatenate")                                           \
    DEC_OP(63, SUBPIECE, "Truncate")                                           \
    DEC_OP(64, CAST, "Cast from one data-type to another")                     \
    DEC_OP(65, PTRADD, "Index into an array ([])")                             \
    DEC_OP(66, PTRSUB, "Drill down to a sub-field  (->)")                      \
    DEC_OP(67, SEGMENTOP, "Look-up a segmented address")                       \
    DEC_OP(68, CPOOLREF, "Recover a value from the constant pool")             \
    DEC_OP(69, NEW, "Allocate a new object (new)")                             \
    DEC_OP(70, INSERT, "Insert a bit-range")                                   \
    DEC_OP(71, EXTRACT, "Extract a bit-range")                                 \
    DEC_OP(72, POPCOUNT, "Count the 1-bits")                                   \
    DEC_OP(73, LZCOUNT, "Count the leading 0-bits")                            \
    DEC_OP(74, MAX, "Value indicating the end of the op-code values")

#define OP(opname) SLEIGH_CPUI_##opname

typedef enum {
#define DEC_OP(oid, oname, odesc) OP(oname) = oid,
#define INV_OP(oid, oname, odesc)
    OPS_X
#undef DEC_OP
#undef INV_OP
} sleigh_opcode_t;

typedef void* sleigh_ctx_t;
typedef void* sleigh_address_space_t;

typedef struct {
    sleigh_address_space_t space;
    uint64_t               offset;
} sleigh_address_t;

typedef struct {
    sleigh_address_space_t space;
    uint64_t               offset;
    uint32_t               size;
} sleigh_varnode_t;

typedef struct {
    char             name[32];
    sleigh_varnode_t varnode;
} sleigh_register_t;

typedef struct {
    sleigh_address_t pc;
    uint32_t         uniq;
    uint32_t         order;
} sleigh_seqnum_t;

typedef struct {
    sleigh_seqnum_t   seq;
    sleigh_opcode_t   opcode;
    sleigh_varnode_t* output; /* NULL if no output */
    sleigh_varnode_t* inputs;
    uint32_t          inputs_count;
} sleigh_pcodeop_t;

typedef enum {
    SLEIGH_ERROR_TYPE_NOERROR = 0,
    SLEIGH_ERROR_TYPE_GENERIC = 1,
    SLEIGH_ERROR_TYPE_UNIMPL  = 2,
    SLEIGH_ERROR_TYPE_BADDATA = 3,
} sleigh_error_type_t;

typedef struct {
    sleigh_error_type_t type;
    const char*         text;
} sleigh_error_t;

typedef struct {
    sleigh_address_t  address;
    uint32_t          length;
    const char*       asm_mnem;
    const char*       asm_body;
    sleigh_pcodeop_t* ops;
    unsigned int      ops_count;
} sleigh_translation_t;

typedef struct {
    sleigh_error_t        error;
    sleigh_translation_t* instructions;
    uint32_t              instructions_count;
} sleigh_translation_result_t;

sleigh_ctx_t sleigh_create_context(sleigh_arch_t arch, sleigh_processor_t proc);
void         sleigh_destroy_context(sleigh_ctx_t ctx);

const char* sleigh_get_register_name(sleigh_ctx_t      ctx,
                                     sleigh_varnode_t* varnode);

bool sleigh_get_register(sleigh_ctx_t _ctx, const char* name,
                         sleigh_varnode_t* reg);
void sleigh_get_all_registers(sleigh_ctx_t ctx, sleigh_register_t** registers,
                              size_t* size);

sleigh_translation_result_t*
sleigh_translate(sleigh_ctx_t _ctx, const uint8_t* bytes, uint32_t num_bytes,
                 uint64_t address, uint32_t max_instructions,
                 int bb_terminating);
void sleigh_destroy_translation_result(sleigh_translation_result_t* r);

const char*            sleigh_get_space_name(sleigh_address_space_t space);
sleigh_address_space_t sleigh_get_space_by_name(sleigh_ctx_t ctx,
                                                const char*  name);

bool sleigh_varnode_is_register(sleigh_varnode_t* varnode);
bool sleigh_varnode_is_unique(sleigh_varnode_t* varnode);
bool sleigh_varnode_is_const(sleigh_varnode_t* varnode);
sleigh_address_space_t
sleigh_varnode_get_const_space(sleigh_varnode_t* varnode);

const char* sleigh_get_last_error();
const char* sleigh_opcode_name(sleigh_opcode_t op);

#ifdef __cplusplus
}
#endif

#endif
