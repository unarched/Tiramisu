// tiramisu/src/trt/bridge_dstorage.cpp
// DirectStorage (dstorage.dll) bridge.
//
// DirectStorage is a Windows 11 GPU-asset-streaming API. Tiramisu does not
// implement it; this bridge registers the module so LoadLibrary/GetProcAddress
// succeed and reports honest failure (E_NOTIMPL) so games can fall back to
// standard file I/O instead of crashing on a missing DLL.
#include "bridge_dstorage.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>

namespace {
namespace dstoragelog { static void line(const char* s) { trt_core_log(s); } }
#define log_line(s_) dstoragelog::line(s_)
}

extern "C" {

// DStorageGetFactory is the single entry point games use.
// Signature: HRESULT DStorageGetFactory(REFIID riid, void** ppv);
// We return E_NOTIMPL (0x80004001) so the caller falls back.
static constexpr unsigned long E_NOTIMPL_ = 0x80004001UL;

long TRT_GUEST_ABI dstorage_DStorageGetFactory(const void* riid, void** ppv) {
    char line[160];
    snprintf(line, sizeof(line),
             "dstorage: DStorageGetFactory -> E_NOTIMPL (DirectStorage not "
             "implemented; game should fall back to standard I/O)");
    log_line(line);
    if (ppv) *ppv = nullptr;
    return (long)E_NOTIMPL_;
}

long TRT_GUEST_ABI dstorage_DStorageSetConfiguration(const void* config) {
    (void)config;
    return 0; // S_OK: accept configuration
}

long TRT_GUEST_ABI dstorage_DStorageSetConfiguration1(const void* config) {
    (void)config;
    return 0; // S_OK: accept configuration
}

long TRT_GUEST_ABI dstorage_DStorageCreateCompressionCodec(u32 format, u32 threads, const void* riid, void** ppv) {
    (void)format; (void)threads; (void)riid;
    if (ppv) *ppv = nullptr;
    return (long)E_NOTIMPL_;
}

}  // extern "C"

extern "C" int trt_bridge_register_dstorage(void) {
    static const trt_named_fn k_fns[] = {
        {"DStorageGetFactory", (void*)&dstorage_DStorageGetFactory},
        {"DStorageSetConfiguration", (void*)&dstorage_DStorageSetConfiguration},
        {"DStorageSetConfiguration1", (void*)&dstorage_DStorageSetConfiguration1},
        {"DStorageCreateCompressionCodec", (void*)&dstorage_DStorageCreateCompressionCodec},
    };
    trt_module_register("dstorage.dll", TRT_ROUTE_BUILTIN, k_fns,
                        (int)(sizeof(k_fns) / sizeof(k_fns[0])));
    trt_module_register("dstoragecore.dll", TRT_ROUTE_BUILTIN, k_fns,
                        (int)(sizeof(k_fns) / sizeof(k_fns[0])));
    return 0;
}