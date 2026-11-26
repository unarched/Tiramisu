// tiramisu/src/trt/bridge_msvcrt.h
// MSVCRT (msvcrt.dll) C-runtime bridge for MinGW / GCC / legacy Win64 PEs.
#ifndef TIRAMISU_BRIDGE_MSVCRT_H
#define TIRAMISU_BRIDGE_MSVCRT_H

#include "trt.h"

#ifdef __cplusplus
extern "C" {
#endif

int trt_bridge_register_msvcrt(void);
int trt_bridge_register_vcruntime_fallback(void);

#ifdef __cplusplus
}
#endif

#endif
