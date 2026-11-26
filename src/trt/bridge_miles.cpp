// tiramisu/src/trt/bridge_miles.cpp
// Miles Sound System (RAD Game Tools) bridge — stubs.
//
// Miles Sound System is a legacy audio middleware used by older games.
// Tiramisu does not implement it; these stubs let LoadLibrary/GetProcAddress
// succeed and return success so games proceed past audio init.
#include "bridge_miles.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>

namespace {
namespace mileslog { static void line(const char* s) { trt_core_log(s); } }
#define log_line(s_) mileslog::line(s_)
}

extern "C" {

static const int MILES_SUCCESS = 1;
static unsigned long long s_miles_sample = 0x77100001;
static unsigned long long s_miles_stream = 0x77100002;
static unsigned long long s_miles_provider = 0x77100003;

// Core
int TRT_GUEST_ABI miles_AIL_startup(void) { log_line("miles: AIL_startup (stub)"); return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_shutdown(void) { return MILES_SUCCESS; }
void* TRT_GUEST_ABI miles_AIL_allocate_sample_handle(void* dig) { return (void*)&s_miles_sample; }
int TRT_GUEST_ABI miles_AIL_free_sample_handle(void* sam) { return MILES_SUCCESS; }
void* TRT_GUEST_ABI miles_AIL_open_digital_driver(unsigned rate, unsigned bits, int channels, unsigned flags) { return (void*)1; }
int TRT_GUEST_ABI miles_AIL_close_digital_driver(void* dig) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_set_sample_volume(void* sam, int vol) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_set_sample_pan(void* sam, int pan) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_start_sample(void* sam) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_stop_sample(void* sam) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_end_sample(void* sam) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_sample_status(void* sam) { return 0; } // 0 = done
int TRT_GUEST_ABI miles_AIL_load_sample_buffer(void* sam, unsigned index, const void* data, unsigned len) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_service(void) { return MILES_SUCCESS; }

// 3D audio
void* TRT_GUEST_ABI miles_AIL_3D_provider_open(void* dig, const char* name) { return (void*)&s_miles_provider; }
int TRT_GUEST_ABI miles_AIL_3D_provider_close(void* prov) { return MILES_SUCCESS; }

// Stream
void* TRT_GUEST_ABI miles_AIL_open_stream(void* dig, const char* filename, int stream_flags) { return (void*)&s_miles_stream; }
int TRT_GUEST_ABI miles_AIL_close_stream(void* stream) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_start_stream(void* stream) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_stop_stream(void* stream) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_pause_stream(void* stream, int pause) { return MILES_SUCCESS; }
int TRT_GUEST_ABI miles_AIL_set_stream_volume(void* stream, int vol) { return MILES_SUCCESS; }

}  // extern "C"

extern "C" int trt_bridge_register_miles(void) {
    static const trt_named_fn k_fns[] = {
        {"AIL_startup", (void*)&miles_AIL_startup},
        {"AIL_shutdown", (void*)&miles_AIL_shutdown},
        {"AIL_allocate_sample_handle", (void*)&miles_AIL_allocate_sample_handle},
        {"AIL_free_sample_handle", (void*)&miles_AIL_free_sample_handle},
        {"AIL_open_digital_driver", (void*)&miles_AIL_open_digital_driver},
        {"AIL_close_digital_driver", (void*)&miles_AIL_close_digital_driver},
        {"AIL_set_sample_volume", (void*)&miles_AIL_set_sample_volume},
        {"AIL_set_sample_pan", (void*)&miles_AIL_set_sample_pan},
        {"AIL_start_sample", (void*)&miles_AIL_start_sample},
        {"AIL_stop_sample", (void*)&miles_AIL_stop_sample},
        {"AIL_end_sample", (void*)&miles_AIL_end_sample},
        {"AIL_sample_status", (void*)&miles_AIL_sample_status},
        {"AIL_load_sample_buffer", (void*)&miles_AIL_load_sample_buffer},
        {"AIL_service", (void*)&miles_AIL_service},
        {"AIL_3D_provider_open", (void*)&miles_AIL_3D_provider_open},
        {"AIL_3D_provider_close", (void*)&miles_AIL_3D_provider_close},
        {"AIL_open_stream", (void*)&miles_AIL_open_stream},
        {"AIL_close_stream", (void*)&miles_AIL_close_stream},
        {"AIL_start_stream", (void*)&miles_AIL_start_stream},
        {"AIL_stop_stream", (void*)&miles_AIL_stop_stream},
        {"AIL_pause_stream", (void*)&miles_AIL_pause_stream},
        {"AIL_set_stream_volume", (void*)&miles_AIL_set_stream_volume},
    };
    trt_module_register("mss32.dll", TRT_ROUTE_BUILTIN, k_fns, (int)(sizeof(k_fns)/sizeof(k_fns[0])));
    trt_module_register("miles.dll", TRT_ROUTE_BUILTIN, k_fns, (int)(sizeof(k_fns)/sizeof(k_fns[0])));
    return 0;
}
