// tiramisu/tests/test_middleware_bridges.cpp
// Unit tests for expanded audio and video middleware bridges:
// Wwise, Bink Video, Miles Sound System, and CriWare.
#include "../src/trt/trt.h"
#include "../src/trt/bridge_wwise.h"
#include "../src/trt/bridge_bink.h"
#include "../src/trt/bridge_miles.h"
#include "../src/trt/bridge_criware.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(cond, msg) \
  do { \
    if (!(cond)) { \
      fprintf(stderr, "FAIL [%s:%d]: %s\n", __FILE__, __LINE__, msg); \
      exit(1); \
    } else { \
      printf("  PASS %s\n", msg); \
    } \
  } while (0)

extern "C" {
// Declare bridge functions with TRT_GUEST_ABI (ms_abi on Linux)
int TRT_GUEST_ABI wwise_AK_SoundEngine_Init(void* settings, void* platform);
int TRT_GUEST_ABI wwise_AK_SoundEngine_Term(void);
unsigned TRT_GUEST_ABI wwise_AK_SoundEngine_IsInitialized(void);
unsigned TRT_GUEST_ABI wwise_AK_SoundEngine_GetIDFromString(const char* str);
void* TRT_GUEST_ABI wwise_AK_MemoryMgr_Malloc(unsigned size);
void TRT_GUEST_ABI wwise_AK_MemoryMgr_Free(void* p);
unsigned TRT_GUEST_ABI wwise_AK_SoundEngine_PostEvent(const char* event_name, unsigned game_obj, unsigned flags, void* cb, void* cookie);
unsigned TRT_GUEST_ABI wwise_AK_SoundEngine_PostEventID(unsigned event_id, unsigned game_obj, unsigned flags, void* cb, void* cookie);

struct BinkHeader {
  unsigned int Width;
  unsigned int Height;
  unsigned int Frames;
  unsigned int FrameNum;
  unsigned int LastFrameNum;
  unsigned int FrameRate;
  unsigned int FrameRateDiv;
  unsigned int ReadError;
  unsigned int OpenFlags;
  unsigned int BinkType;
  unsigned int Size;
  unsigned int FrameSize;
  unsigned int SndSize;
  unsigned int NumTracks;
};
void* TRT_GUEST_ABI bink_BinkOpen(const void* file, unsigned flags);
void* TRT_GUEST_ABI bink_BinkOpenDirect(const char* name, unsigned flags);
int TRT_GUEST_ABI bink_BinkClose(void* bnk);
int TRT_GUEST_ABI bink_BinkDoFrame(void* bnk);
int TRT_GUEST_ABI bink_BinkNextFrame(void* bnk);
int TRT_GUEST_ABI bink_BinkWait(void* bnk);
int TRT_GUEST_ABI bink_BinkShouldSkip(void* bnk);
unsigned TRT_GUEST_ABI bink_BinkGetFrameNum(void* bnk);

int TRT_GUEST_ABI miles_AIL_startup(void);
int TRT_GUEST_ABI miles_AIL_shutdown(void);
void* TRT_GUEST_ABI miles_AIL_allocate_sample_handle(void* dig);
int TRT_GUEST_ABI miles_AIL_free_sample_handle(void* sam);
void* TRT_GUEST_ABI miles_AIL_open_stream(void* dig, const char* filename, int stream_flags);
int TRT_GUEST_ABI miles_AIL_sample_status(void* sam);

int TRT_GUEST_ABI cri_CriAtom_Initialize(const void* config);
int TRT_GUEST_ABI cri_CriAtom_Finalize(void);
void* TRT_GUEST_ABI cri_criAtomExPlayer_Create(const void* config, void* work, unsigned work_size);
int TRT_GUEST_ABI cri_criAtomExPlayer_Destroy(void* player);
int TRT_GUEST_ABI cri_CriMana_Initialize(const void* config);
int TRT_GUEST_ABI cri_CriMana_Finalize(void);
void* TRT_GUEST_ABI cri_criManaPlayer_Create(const void* config, void* work, unsigned work_size);

// DirectStorage
int trt_bridge_register_dstorage(void);
long TRT_GUEST_ABI dstorage_DStorageGetFactory(const void* riid, void** ppv);
long TRT_GUEST_ABI dstorage_DStorageSetConfiguration(const void* config);
long TRT_GUEST_ABI dstorage_DStorageSetConfiguration1(const void* config);

// D3D9 PERF
int trt_bridge_register_d3d9(void);
void TRT_GUEST_ABI trt_D3DPERF_SetOptions(unsigned int opt);
int TRT_GUEST_ABI trt_D3DPERF_QueryRepeatFrame(void);
unsigned int TRT_GUEST_ABI trt_D3DPERF_GetStatus(void* dev);
}

int main() {
  printf("test_middleware_bridges: audio & video middleware bridges\n");

  // 1. Wwise tests
  printf("-- Wwise (AK::SoundEngine)\n");
  CHECK(trt_bridge_register_wwise() == 0, "trt_bridge_register_wwise succeeds");
  CHECK(wwise_AK_SoundEngine_Init(nullptr, nullptr) == 0, "wwise Init succeeds");
  CHECK(wwise_AK_SoundEngine_IsInitialized() == 1, "wwise IsInitialized returns 1");

  // Memory manager
  void* mem = wwise_AK_MemoryMgr_Malloc(256);
  CHECK(mem != nullptr, "wwise MemoryMgr_Malloc returns valid memory");
  memset(mem, 0xAA, 256);
  CHECK(((unsigned char*)mem)[0] == 0xAA && ((unsigned char*)mem)[255] == 0xAA,
        "wwise allocated memory is writable");
  wwise_AK_MemoryMgr_Free(mem);
  CHECK(true, "wwise MemoryMgr_Free succeeds without fault");

  // FNV-1a hash
  unsigned hash_null = wwise_AK_SoundEngine_GetIDFromString(nullptr);
  unsigned hash_empty = wwise_AK_SoundEngine_GetIDFromString("");
  CHECK(hash_null == 0 && hash_empty == 0, "GetIDFromString returns 0 for null/empty");

  unsigned hash1 = wwise_AK_SoundEngine_GetIDFromString("Play_Footstep");
  unsigned hash2 = wwise_AK_SoundEngine_GetIDFromString("play_footstep");
  unsigned hash3 = wwise_AK_SoundEngine_GetIDFromString("Stop_Music");
  CHECK(hash1 != 0, "GetIDFromString returns non-zero hash for valid string");
  CHECK(hash1 == hash2, "GetIDFromString is case-insensitive (Wwise convention)");
  CHECK(hash1 != hash3, "GetIDFromString generates distinct hashes for distinct events");

  // PostEvent
  unsigned play_id1 = wwise_AK_SoundEngine_PostEvent("Play_BGM", 1, 0, nullptr, nullptr);
  unsigned play_id2 = wwise_AK_SoundEngine_PostEvent("Play_SFX", 1, 0, nullptr, nullptr);
  CHECK(play_id1 != 0 && play_id2 != 0, "PostEvent returns valid non-zero playing ID");
  CHECK(play_id1 != play_id2, "PostEvent returns unique playing IDs");

  unsigned play_id3 = wwise_AK_SoundEngine_PostEventID(hash1, 1, 0, nullptr, nullptr);
  CHECK(play_id3 != 0, "PostEventID returns valid non-zero playing ID");
  CHECK(wwise_AK_SoundEngine_Term() == 0, "wwise Term succeeds");

  // 2. Bink Video tests
  printf("-- Bink 2 Video\n");
  CHECK(trt_bridge_register_bink() == 0, "trt_bridge_register_bink succeeds");
  void* bnk = bink_BinkOpen("fake.bik", 0);
  CHECK(bnk != nullptr, "BinkOpen returns non-null dummy structure");
  BinkHeader* hdr = (BinkHeader*)bnk;
  CHECK(hdr->Width == 1920 && hdr->Height == 1080, "Bink dummy header has 1080p resolution");
  CHECK(hdr->Frames >= 1 && hdr->FrameNum == 1, "Bink dummy header indicates frame ready");

  CHECK(bink_BinkShouldSkip(bnk) == 1, "BinkShouldSkip indicates skip to main menu");
  CHECK(bink_BinkDoFrame(bnk) == 0, "BinkDoFrame succeeds");
  CHECK(bink_BinkNextFrame(bnk) == 0, "BinkNextFrame succeeds");
  CHECK(bink_BinkWait(bnk) == 0, "BinkWait returns ready (0)");
  CHECK(bink_BinkGetFrameNum(bnk) == 1, "BinkGetFrameNum returns 1");
  CHECK(bink_BinkClose(bnk) == 0, "BinkClose succeeds");

  void* bnk_dir = bink_BinkOpenDirect("intro.bik", 0);
  CHECK(bnk_dir != nullptr, "BinkOpenDirect returns non-null dummy structure");
  CHECK(bink_BinkClose(bnk_dir) == 0, "BinkClose succeeds for direct open");

  // 3. Miles Sound System tests
  printf("-- Miles Sound System\n");
  CHECK(trt_bridge_register_miles() == 0, "trt_bridge_register_miles succeeds");
  CHECK(miles_AIL_startup() == 1, "AIL_startup returns success (1)");
  void* sample = miles_AIL_allocate_sample_handle(nullptr);
  CHECK(sample != nullptr, "AIL_allocate_sample_handle returns valid non-null handle");
  CHECK(miles_AIL_sample_status(sample) == 0, "AIL_sample_status returns done (0)");
  CHECK(miles_AIL_free_sample_handle(sample) == 1, "AIL_free_sample_handle succeeds");

  void* stream = miles_AIL_open_stream(nullptr, "music.wav", 0);
  CHECK(stream != nullptr, "AIL_open_stream returns valid non-null handle");
  CHECK(miles_AIL_shutdown() == 1, "AIL_shutdown returns success (1)");

  // 4. CriWare tests
  printf("-- CriWare (Atom + Mana)\n");
  CHECK(trt_bridge_register_criware() == 0, "trt_bridge_register_criware succeeds");
  CHECK(cri_CriAtom_Initialize(nullptr) == 0, "CriAtom_Initialize succeeds");
  void* atom_player = cri_criAtomExPlayer_Create(nullptr, nullptr, 0);
  CHECK(atom_player != nullptr, "criAtomExPlayer_Create returns valid non-null handle");
  CHECK(cri_criAtomExPlayer_Destroy(atom_player) == 0, "criAtomExPlayer_Destroy succeeds");
  CHECK(cri_CriAtom_Finalize() == 0, "CriAtom_Finalize succeeds");

  CHECK(cri_CriMana_Initialize(nullptr) == 0, "CriMana_Initialize succeeds");
  void* mana_player = cri_criManaPlayer_Create(nullptr, nullptr, 0);
  CHECK(mana_player != nullptr, "criManaPlayer_Create returns valid non-null handle");
  CHECK(cri_CriMana_Finalize() == 0, "CriMana_Finalize succeeds");

  // 5. DirectStorage
  printf("-- DirectStorage\n");
  CHECK(trt_bridge_register_dstorage() == 0, "trt_bridge_register_dstorage succeeds");
  CHECK(dstorage_DStorageSetConfiguration(nullptr) == 0, "DStorageSetConfiguration succeeds");
  CHECK(dstorage_DStorageSetConfiguration1(nullptr) == 0, "DStorageSetConfiguration1 succeeds");
  void* factory = nullptr;
  CHECK(dstorage_DStorageGetFactory(nullptr, &factory) != 0, "DStorageGetFactory reports honest E_NOTIMPL");
  CHECK(factory == nullptr, "DStorageGetFactory nulls out factory pointer");

  // 6. D3D9 PERF
  printf("-- D3D9 PERF\n");
  CHECK(trt_bridge_register_d3d9() == 0, "trt_bridge_register_d3d9 succeeds");
  trt_D3DPERF_SetOptions(1);
  CHECK(trt_D3DPERF_QueryRepeatFrame() == 0, "D3DPERF_QueryRepeatFrame returns 0");
  CHECK(trt_D3DPERF_GetStatus(nullptr) == 0, "D3DPERF_GetStatus returns 0");

  printf("RESULT: ALL PASS\n");
  return 0;
}
