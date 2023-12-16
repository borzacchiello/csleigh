#ifndef SLEIGH_FLOAT_H
#define SLEIGH_FLOAT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "sleigh.h"

typedef void* sleigh_float_format_t;

sleigh_float_format_t sleigh_get_host_float(sleigh_ctx_t _ctx, int32_t size);

int32_t  float_format_get_size(sleigh_float_format_t ff);
uint64_t float_format_get_encoding(sleigh_float_format_t ff, double val);
double float_format_get_host_float(sleigh_float_format_t ff, uint64_t encoding);
uint64_t float_format_convert_encoding(sleigh_float_format_t from,
                                       sleigh_float_format_t to,
                                       uint64_t              encoding);

uint64_t float_format_op_Equal(sleigh_float_format_t ff, uint64_t a,
                               uint64_t b);
uint64_t float_format_op_NotEqual(sleigh_float_format_t ff, uint64_t a,
                                  uint64_t b);
uint64_t float_format_op_Less(sleigh_float_format_t ff, uint64_t a, uint64_t b);
uint64_t float_format_op_LessEqual(sleigh_float_format_t ff, uint64_t a,
                                   uint64_t b);
uint64_t float_format_op_Nan(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Add(sleigh_float_format_t ff, uint64_t a, uint64_t b);
uint64_t float_format_op_Div(sleigh_float_format_t ff, uint64_t a, uint64_t b);
uint64_t float_format_op_Mult(sleigh_float_format_t ff, uint64_t a, uint64_t b);
uint64_t float_format_op_Sub(sleigh_float_format_t ff, uint64_t a, uint64_t b);
uint64_t float_format_op_Neg(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Abs(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Sqrt(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Trunc(sleigh_float_format_t ff, uint64_t a,
                               uint32_t sizeout);
uint64_t float_format_op_Ceil(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Floor(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Round(sleigh_float_format_t ff, uint64_t a);
uint64_t float_format_op_Int2Float(sleigh_float_format_t ff, uint64_t a,
                                   uint32_t sizein);

#ifdef __cplusplus
}
#endif

#endif
