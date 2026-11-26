// tiramisu/src/trt/bridge_criware.cpp
// CriWare (CRI Middleware) bridge — stubs.
//
// CRI Middleware (ADX2/CriAtom/CriMana) is used by many Japanese games.
// Tiramisu does not implement it; these stubs let LoadLibrary/GetProcAddress
// succeed and return success so games proceed past audio init. Audio
// playback remains unavailable.
#include "bridge_criware.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>

namespace {
namespace crilog { static void line(const char* s) { trt_core_log(s); } }
#define log_line(s_) crilog::line(s_)
}

extern "C" {

static const int CRI_SUCCESS = 0;
static unsigned long long s_cri_atom_player = 0x77200001;
static unsigned long long s_cri_mana_player = 0x77200002;

// ---- CriAtom (audio) ----
int TRT_GUEST_ABI cri_CriAtom_Initialize(const void* config) {
    log_line("criware: CriAtom_Initialize -> success (stub)");
    return CRI_SUCCESS;
}
int TRT_GUEST_ABI cri_CriAtom_Finalize(void) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_CriAtom_ExecuteMain(void) { return CRI_SUCCESS; }
void* TRT_GUEST_ABI cri_criAtomExPlayer_Create(const void* config, void* work, unsigned work_size) {
    log_line("criware: criAtomExPlayer_Create -> non-null handle (stub)");
    return (void*)&s_cri_atom_player;
}
int TRT_GUEST_ABI cri_criAtomExPlayer_Destroy(void* player) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_SetCueId(void* player, unsigned cue_id) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_SetCueName(void* player, const char* name) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_Start(void* player) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_Stop(void* player) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_Pause(void* player, int pause) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_SetVolume(void* player, float vol) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criAtomExPlayer_Update(void* player) { return CRI_SUCCESS; }
unsigned TRT_GUEST_ABI cri_criAtomExAcb_LoadAcbFile(const char* path, void* work, unsigned work_size, unsigned* acb_h) {
    char buf[512];
    snprintf(buf, sizeof(buf), "criware: LoadAcbFile('%s') -> stub (not loaded)", path ? path : "(null)");
    log_line(buf);
    if (acb_h) *acb_h = 1;
    return CRI_SUCCESS;
}
int TRT_GUEST_ABI cri_criAtomExAcb_Release(unsigned acb_h) { return CRI_SUCCESS; }

// ---- CriMana (video) ----
int TRT_GUEST_ABI cri_CriMana_Initialize(const void* config) {
    log_line("criware: CriMana_Initialize -> success (stub)");
    return CRI_SUCCESS;
}
int TRT_GUEST_ABI cri_CriMana_Finalize(void) { return CRI_SUCCESS; }
void* TRT_GUEST_ABI cri_criManaPlayer_Create(const void* config, void* work, unsigned work_size) {
    log_line("criware: criManaPlayer_Create -> non-null handle (stub)");
    return (void*)&s_cri_mana_player;
}
int TRT_GUEST_ABI cri_criManaPlayer_Destroy(void* player) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criManaPlayer_SetFile(void* player, const char* path) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criManaPlayer_Start(void* player) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criManaPlayer_Stop(void* player) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_criManaPlayer_Update(void* player) { return CRI_SUCCESS; }

// ---- CriFs (file system) ----
int TRT_GUEST_ABI cri_CriFs_Initialize(const void* config) { return CRI_SUCCESS; }
int TRT_GUEST_ABI cri_CriFs_Finalize(void) { return CRI_SUCCESS; }

}  // extern "C"

extern "C" int trt_bridge_register_criware(void) {
    static const trt_named_fn k_fns[] = {
        {"CriAtom_Initialize", (void*)&cri_CriAtom_Initialize},
        {"CriAtom_Finalize", (void*)&cri_CriAtom_Finalize},
        {"CriAtom_ExecuteMain", (void*)&cri_CriAtom_ExecuteMain},
        {"criAtomExPlayer_Create", (void*)&cri_criAtomExPlayer_Create},
        {"criAtomExPlayer_Destroy", (void*)&cri_criAtomExPlayer_Destroy},
        {"criAtomExPlayer_SetCueId", (void*)&cri_criAtomExPlayer_SetCueId},
        {"criAtomExPlayer_SetCueName", (void*)&cri_criAtomExPlayer_SetCueName},
        {"criAtomExPlayer_Start", (void*)&cri_criAtomExPlayer_Start},
        {"criAtomExPlayer_Stop", (void*)&cri_criAtomExPlayer_Stop},
        {"criAtomExPlayer_Pause", (void*)&cri_criAtomExPlayer_Pause},
        {"criAtomExPlayer_SetVolume", (void*)&cri_criAtomExPlayer_SetVolume},
        {"criAtomExPlayer_Update", (void*)&cri_criAtomExPlayer_Update},
        {"criAtomExAcb_LoadAcbFile", (void*)&cri_criAtomExAcb_LoadAcbFile},
        {"criAtomExAcb_Release", (void*)&cri_criAtomExAcb_Release},
        {"CriMana_Initialize", (void*)&cri_CriMana_Initialize},
        {"CriMana_Finalize", (void*)&cri_CriMana_Finalize},
        {"criManaPlayer_Create", (void*)&cri_criManaPlayer_Create},
        {"criManaPlayer_Destroy", (void*)&cri_criManaPlayer_Destroy},
        {"criManaPlayer_SetFile", (void*)&cri_criManaPlayer_SetFile},
        {"criManaPlayer_Start", (void*)&cri_criManaPlayer_Start},
        {"criManaPlayer_Stop", (void*)&cri_criManaPlayer_Stop},
        {"criManaPlayer_Update", (void*)&cri_criManaPlayer_Update},
        {"CriFs_Initialize", (void*)&cri_CriFs_Initialize},
        {"CriFs_Finalize", (void*)&cri_CriFs_Finalize},
    };
    trt_module_register("criatom.dll", TRT_ROUTE_BUILTIN, k_fns, (int)(sizeof(k_fns)/sizeof(k_fns[0])));
    trt_module_register("criatomex.dll", TRT_ROUTE_BUILTIN, k_fns, (int)(sizeof(k_fns)/sizeof(k_fns[0])));
    trt_module_register("cri_mana.dll", TRT_ROUTE_BUILTIN, k_fns, (int)(sizeof(k_fns)/sizeof(k_fns[0])));
    return 0;
}
