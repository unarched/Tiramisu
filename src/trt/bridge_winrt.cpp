// tiramisu/src/trt/bridge_winrt.cpp
// BUILTIN bridges for:
//   1. combase.dll + api-ms-win-core-winrt* (RoInitialize, RoActivateInstance,
//      RoGetActivationFactory, HSTRING lifecycle, CoTaskMem*, CoCreateInstance)
//   2. dwrite.dll (DWriteCreateFactory fail-visible)
//   3. uiautomationcore.dll (11 UIA exports fail-visible no-op)
//   4. shcore.dll (DPI / monitor scale factor helpers)
//   5. version.dll (GetFileVersionInfo* + VerQueryValue* with real minimal
//      VS_FIXEDFILEINFO block)
//   6. winhttp.dll (offline fail-visible HTTP session/request surface)
#include "bridge_winrt.h"
#include "bridge_ole.h"
#include "input.h"
#include "thunk.h"
#include "trt.h"

#include <atomic>
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <string.h>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <mutex>
#endif

namespace winrtlog {
static void line(const char* s) { trt_core_log(s); }
}
#define log_line(s_) winrtlog::line(s_)

extern "C" {

extern void TRT_STDCALL trt_SetLastError(u32 err);

namespace {

constexpr i32 S_OK_ = 0;
constexpr i32 E_INVALIDARG_ = (i32)0x80070057;
constexpr i32 E_POINTER_ = (i32)0x80004003;
constexpr i32 E_OUTOFMEMORY_ = (i32)0x8007000E;
constexpr i32 E_NOINTERFACE_ = (i32)0x80004002;
constexpr i32 REGDB_E_CLASSNOTREG_ = (i32)0x80040154;

// ============================================================================
// 1. combase.dll — WinRT Ro* + HSTRING + shared COM base
// ============================================================================

struct trt_hstring {
  u32 magic;     // 0x48535452 ('HSTR') for heap, 0x48524546 ('HREF') for fast-pass
  i32 refs;
  u32 len;       // UTF-16 code units (excluding trailing NUL)
  const u16* ptr;
  u16 buf[1];    // flexible tail for heap strings
};

constexpr u32 HSTR_HEAP_MAGIC = 0x48535452u;
constexpr u32 HSTR_REF_MAGIC  = 0x48524546u;

i32 TRT_GUEST_ABI wrt_WindowsCreateString(const u16* src, u32 len,
                                          void** out_hstr) {
  if (!out_hstr) return E_INVALIDARG_;
  *out_hstr = nullptr;
  if (len == 0) return S_OK_;  // empty HSTRING is guaranteed to be NULL
  if (!src) return E_POINTER_;
  trt_hstring* h =
      (trt_hstring*)malloc(sizeof(trt_hstring) + (size_t)len * sizeof(u16));
  if (!h) return E_OUTOFMEMORY_;
  h->magic = HSTR_HEAP_MAGIC;
  h->refs = 1;
  h->len = len;
  memcpy(h->buf, src, (size_t)len * sizeof(u16));
  h->buf[len] = 0;
  h->ptr = h->buf;
  *out_hstr = (void*)h;
  return S_OK_;
}

// HSTRING_HEADER is 24 bytes on x64; we store a trt_hstring-compatible layout
// or allocate a tracked reference record.
i32 TRT_GUEST_ABI wrt_WindowsCreateStringReference(const u16* src, u32 len,
                                                   void* header,
                                                   void** out_hstr) {
  if (!out_hstr || !header) return E_INVALIDARG_;
  *out_hstr = nullptr;
  if (len == 0) return S_OK_;
  if (!src) return E_POINTER_;
  // Verify NUL termination per WinRT spec
  if (src[len] != 0) return E_INVALIDARG_;
  // Use the caller's 24-byte HSTRING_HEADER to hold {magic, refs, len, ptr}
  struct fast_hstr {
    u32 magic;
    i32 refs;
    u32 len;
    u32 _pad;
    const u16* ptr;
  };
  static_assert(sizeof(fast_hstr) == 24, "HSTRING_HEADER size");
  fast_hstr* fh = (fast_hstr*)header;
  fh->magic = HSTR_REF_MAGIC;
  fh->refs = 1;
  fh->len = len;
  fh->ptr = src;
  *out_hstr = (void*)fh;
  return S_OK_;
}

i32 TRT_GUEST_ABI wrt_WindowsDeleteString(void* hstr) {
  if (!hstr) return S_OK_;
  trt_hstring* h = (trt_hstring*)hstr;
  if (h->magic == HSTR_REF_MAGIC) return S_OK_;
  if (h->magic == HSTR_HEAP_MAGIC) {
    if (--h->refs <= 0) {
      h->magic = 0;
      free(h);
    }
  }
  return S_OK_;
}

i32 TRT_GUEST_ABI wrt_WindowsDuplicateString(void* hstr, void** out_hstr) {
  if (!out_hstr) return E_INVALIDARG_;
  if (!hstr) {
    *out_hstr = nullptr;
    return S_OK_;
  }
  trt_hstring* h = (trt_hstring*)hstr;
  if (h->magic == HSTR_HEAP_MAGIC) {
    ++h->refs;
    *out_hstr = hstr;
    return S_OK_;
  }
  if (h->magic == HSTR_REF_MAGIC) {
    struct fast_hstr {
      u32 magic;
      i32 refs;
      u32 len;
      u32 _pad;
      const u16* ptr;
    };
    const fast_hstr* fh = (const fast_hstr*)hstr;
    return wrt_WindowsCreateString(fh->ptr, fh->len, out_hstr);
  }
  *out_hstr = nullptr;
  return E_INVALIDARG_;
}

const u16* TRT_GUEST_ABI wrt_WindowsGetStringRawBuffer(void* hstr, u32* len) {
  static const u16 k_empty[1] = {0};
  if (!hstr) {
    if (len) *len = 0;
    return k_empty;
  }
  const u32 magic = *(const u32*)hstr;
  if (magic == HSTR_HEAP_MAGIC) {
    const trt_hstring* h = (const trt_hstring*)hstr;
    if (len) *len = h->len;
    return h->ptr;
  }
  if (magic == HSTR_REF_MAGIC) {
    struct fast_hstr {
      u32 magic;
      i32 refs;
      u32 len;
      u32 _pad;
      const u16* ptr;
    };
    const fast_hstr* fh = (const fast_hstr*)hstr;
    if (len) *len = fh->len;
    return fh->ptr ? fh->ptr : k_empty;
  }
  if (len) *len = 0;
  return k_empty;
}

u32 TRT_GUEST_ABI wrt_WindowsGetStringLen(void* hstr) {
  u32 len = 0;
  wrt_WindowsGetStringRawBuffer(hstr, &len);
  return len;
}

i32 TRT_GUEST_ABI wrt_WindowsIsStringEmpty(void* hstr) {
  return wrt_WindowsGetStringLen(hstr) == 0 ? 1 : 0;
}

i32 TRT_GUEST_ABI wrt_WindowsCompareStringOrdinal(void* s1, void* s2,
                                                  i32* result) {
  if (!result) return E_INVALIDARG_;
  u32 l1 = 0, l2 = 0;
  const u16* b1 = wrt_WindowsGetStringRawBuffer(s1, &l1);
  const u16* b2 = wrt_WindowsGetStringRawBuffer(s2, &l2);
  u32 n = l1 < l2 ? l1 : l2;
  for (u32 i = 0; i < n; ++i) {
    if (b1[i] != b2[i]) {
      *result = (b1[i] < b2[i]) ? -1 : 1;
      return S_OK_;
    }
  }
  *result = (l1 == l2) ? 0 : ((l1 < l2) ? -1 : 1);
  return S_OK_;
}

i32 TRT_GUEST_ABI wrt_WindowsConcatString(void* s1, void* s2, void** out) {
  if (!out) return E_INVALIDARG_;
  u32 l1 = 0, l2 = 0;
  const u16* b1 = wrt_WindowsGetStringRawBuffer(s1, &l1);
  const u16* b2 = wrt_WindowsGetStringRawBuffer(s2, &l2);
  if (l1 + l2 == 0) {
    *out = nullptr;
    return S_OK_;
  }
  u16* tmp = (u16*)malloc(((size_t)l1 + l2 + 1) * sizeof(u16));
  if (!tmp) return E_OUTOFMEMORY_;
  if (l1) memcpy(tmp, b1, l1 * sizeof(u16));
  if (l2) memcpy(tmp + l1, b2, l2 * sizeof(u16));
  tmp[l1 + l2] = 0;
  i32 hr = wrt_WindowsCreateString(tmp, l1 + l2, out);
  free(tmp);
  return hr;
}

i32 TRT_GUEST_ABI wrt_RoInitialize(u32 init_type) {
  // RO_INIT_SINGLETHREADED (0) -> COINIT_APARTMENTTHREADED (2)
  // RO_INIT_MULTITHREADED  (1) -> COINIT_MULTITHREADED (0)
  return ole_CoInitializeEx(nullptr, init_type == 0 ? 0x2u : 0x0u);
}

void TRT_GUEST_ABI wrt_RoUninitialize(void) { ole_CoUninitialize(); }

static i32 wrt_offline_activate(const char* cls, void** instance);
static i32 wrt_offline_factory(const char* cls, const void* iid, void** factory);

i32 TRT_GUEST_ABI wrt_RoActivateInstance(void* activatableClassId,
                                         void** instance) {
  if (!instance) return E_POINTER_;
  *instance = nullptr;
  char cls[96] = {};
  u32 len = 0;
  const u16* raw = wrt_WindowsGetStringRawBuffer(activatableClassId, &len);
  if (raw) {
    for (u32 i = 0; i < len && i < sizeof(cls) - 1; ++i) cls[i] = (char)raw[i];
  }
  const i32 hr = wrt_offline_activate(cls, instance);
  if (hr >= 0) return hr;
  char line[160];
  snprintf(line, sizeof(line),
           "winrt: RoActivateInstance('%s') -> REGDB_E_CLASSNOTREG", cls);
  log_line(line);
  return REGDB_E_CLASSNOTREG_;
}

i32 TRT_GUEST_ABI wrt_RoGetActivationFactory(void* activatableClassId,
                                             const void* iid, void** factory) {
  if (!factory) return E_POINTER_;
  *factory = nullptr;
  char cls[96] = {};
  u32 len = 0;
  const u16* raw = wrt_WindowsGetStringRawBuffer(activatableClassId, &len);
  if (raw) {
    for (u32 i = 0; i < len && i < sizeof(cls) - 1; ++i) cls[i] = (char)raw[i];
  }
  const i32 hr = wrt_offline_factory(cls, iid, factory);
  if (hr >= 0) return hr;
  char line[160];
  snprintf(line, sizeof(line),
           "winrt: RoGetActivationFactory('%s') -> REGDB_E_CLASSNOTREG", cls);
  log_line(line);
  return REGDB_E_CLASSNOTREG_;
}

i32 TRT_GUEST_ABI wrt_RoSetErrorReportingFlags(u32 flags) {
  (void)flags;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_GetRestrictedErrorInfo(void** ppRestrictedErrorInfo) {
  if (ppRestrictedErrorInfo) *ppRestrictedErrorInfo = nullptr;
  return 1;  // S_FALSE
}
i32 TRT_GUEST_ABI wrt_SetRestrictedErrorInfo(void* pRestrictedErrorInfo) {
  (void)pRestrictedErrorInfo;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_RoOriginateError(i32 error, void* message) {
  (void)error; (void)message;
  return 1;
}
i32 TRT_GUEST_ABI wrt_RoOriginateErrorW(i32 error, u32 cchMax,
                                        const u16* message) {
  (void)error; (void)cchMax; (void)message;
  return 1;
}
i32 TRT_GUEST_ABI wrt_RoTransformError(i32 oldError, i32 newError,
                                       void* message) {
  (void)oldError; (void)newError; (void)message;
  return 1;
}
i32 TRT_GUEST_ABI wrt_RoGetBufferMarshaler(void** bufferMarshaler) {
  return ole_CoCreateFreeThreadedMarshaler(nullptr, bufferMarshaler);
}

// ============================================================================
// 2. dwrite.dll — DirectWrite fail-visible bridge
// ============================================================================

i32 TRT_GUEST_ABI dw_DWriteCreateFactory(u32 factoryType, const void* iid,
                                         void** factory) {
  (void)factoryType; (void)iid;
  if (factory) *factory = nullptr;
  log_line("dwrite: DWriteCreateFactory -> E_NOINTERFACE (no DirectWrite on console)");
  return E_NOINTERFACE_;
}

// ============================================================================
// 3. uiautomationcore.dll — UI Automation fail-visible no-op bridge
// ============================================================================

i64 TRT_GUEST_ABI uia_UiaReturnRawElementProvider(void* hwnd, u64 wParam,
                                                  i64 lParam, void* el) {
  (void)hwnd; (void)wParam; (void)lParam; (void)el;
  return 0;
}
i32 TRT_GUEST_ABI uia_UiaHostProviderFromHwnd(void* hwnd, void** ppProvider) {
  (void)hwnd;
  if (ppProvider) *ppProvider = nullptr;
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI uia_UiaRaiseAutomationPropertyChangedEvent(
    void* pProvider, i32 id, i32 oldVal, i32 newVal) {
  (void)pProvider; (void)id; (void)oldVal; (void)newVal;
  return S_OK_;
}
i32 TRT_GUEST_ABI uia_UiaRaiseAutomationEvent(void* pProvider, i32 id) {
  (void)pProvider; (void)id;
  return S_OK_;
}
i32 TRT_GUEST_ABI uia_UiaRaiseStructureChangedEvent(void* pProvider,
                                                    i32 structureChangeType,
                                                    i32* pRuntimeId,
                                                    i32 cRuntimeIdLen) {
  (void)pProvider; (void)structureChangeType;
  (void)pRuntimeId; (void)cRuntimeIdLen;
  return S_OK_;
}
i32 TRT_GUEST_ABI uia_UiaRaiseNotificationEvent(void* provider,
                                                i32 notificationKind,
                                                i32 notificationProcessing,
                                                void* displayString,
                                                void* activityId) {
  (void)provider; (void)notificationKind; (void)notificationProcessing;
  (void)displayString; (void)activityId;
  return S_OK_;
}
i32 TRT_GUEST_ABI uia_UiaClientsAreListening(void) { return 0; }
i32 TRT_GUEST_ABI uia_UiaDisconnectAllProviders(void) { return S_OK_; }
i32 TRT_GUEST_ABI uia_UiaDisconnectProvider(void* pProvider) {
  (void)pProvider;
  return S_OK_;
}
i32 TRT_GUEST_ABI uia_UiaGetReservedNotSupportedValue(void** punkNotSupported) {
  if (punkNotSupported) *punkNotSupported = nullptr;
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI uia_UiaLookupId(i32 type, const void* pGuid) {
  (void)type; (void)pGuid;
  return 0;
}

// ============================================================================
// 4. shcore.dll — DPI / monitor scale factor helpers
// ============================================================================

i32 TRT_GUEST_ABI shc_GetDpiForMonitor(void* hmonitor, i32 dpiType, u32* dpiX,
                                       u32* dpiY) {
  (void)hmonitor; (void)dpiType;
  if (!dpiX || !dpiY) return E_INVALIDARG_;
  *dpiX = 96;
  *dpiY = 96;
  return S_OK_;
}
i32 TRT_GUEST_ABI shc_SetProcessDpiAwareness(i32 value) {
  (void)value;
  return S_OK_;
}
i32 TRT_GUEST_ABI shc_GetProcessDpiAwareness(void* hprocess, i32* value) {
  (void)hprocess;
  if (!value) return E_INVALIDARG_;
  *value = 2;  // PROCESS_PER_MONITOR_DPI_AWARE
  return S_OK_;
}
i32 TRT_GUEST_ABI shc_GetScaleFactorForMonitor(void* hMon, i32* pScale) {
  (void)hMon;
  if (!pScale) return E_INVALIDARG_;
  *pScale = 100;  // 100%
  return S_OK_;
}

// ============================================================================
// 5. version.dll — File version info block (synthesized VS_FIXEDFILEINFO 1.0)
// ============================================================================

struct ver_block {
  u16 wLength;
  u16 wValueLength;
  u16 wType;
  u16 szKey[16];  // L"VS_VERSION_INFO"
  u16 Padding1;
  // VS_FIXEDFILEINFO (52 bytes)
  u32 dwSignature;       // 0xFEEF04BD
  u32 dwStrucVersion;    // 0x00010000
  u32 dwFileVersionMS;   // 0x00010000 (1.0)
  u32 dwFileVersionLS;   // 0x00000000 (0.0)
  u32 dwProductVersionMS;
  u32 dwProductVersionLS;
  u32 dwFileFlagsMask;
  u32 dwFileFlags;
  u32 dwFileOS;          // VOS_NT_WINDOWS32 (0x00040004)
  u32 dwFileType;        // VFT_APP (1)
  u32 dwFileSubtype;
  u32 dwFileDateMS;
  u32 dwFileDateLS;
};

void fill_ver_block(ver_block* b) {
  memset(b, 0, sizeof(*b));
  b->wLength = (u16)sizeof(*b);
  b->wValueLength = 52;
  b->wType = 0;
  static const char k_key[] = "VS_VERSION_INFO";
  for (int i = 0; i < 15; ++i) b->szKey[i] = (u16)k_key[i];
  b->dwSignature = 0xFEEF04BDu;
  b->dwStrucVersion = 0x00010000u;
  b->dwFileVersionMS = 0x00010000u;
  b->dwProductVersionMS = 0x00010000u;
  b->dwFileOS = 0x00040004u;
  b->dwFileType = 1u;
}

u32 TRT_GUEST_ABI ver_GetFileVersionInfoSizeW(const u16* filename,
                                              u32* handle) {
  if (handle) *handle = 0;
  if (!filename || !filename[0]) {
    trt_SetLastError(2);
    return 0;
  }
  return (u32)sizeof(ver_block);
}
u32 TRT_GUEST_ABI ver_GetFileVersionInfoSizeA(const char* filename,
                                              u32* handle) {
  if (handle) *handle = 0;
  if (!filename || !filename[0]) {
    trt_SetLastError(2);
    return 0;
  }
  return (u32)sizeof(ver_block);
}
u32 TRT_GUEST_ABI ver_GetFileVersionInfoSizeExW(u32 flags, const u16* filename,
                                                u32* handle) {
  (void)flags;
  return ver_GetFileVersionInfoSizeW(filename, handle);
}
int TRT_GUEST_ABI ver_GetFileVersionInfoW(const u16* filename, u32 handle,
                                          u32 len, void* data) {
  (void)handle;
  if (!filename || !data || len < sizeof(ver_block)) {
    trt_SetLastError(122);  // ERROR_INSUFFICIENT_BUFFER
    return 0;
  }
  fill_ver_block((ver_block*)data);
  return 1;
}
int TRT_GUEST_ABI ver_GetFileVersionInfoA(const char* filename, u32 handle,
                                          u32 len, void* data) {
  (void)handle;
  if (!filename || !data || len < sizeof(ver_block)) {
    trt_SetLastError(122);
    return 0;
  }
  fill_ver_block((ver_block*)data);
  return 1;
}
int TRT_GUEST_ABI ver_GetFileVersionInfoExW(u32 flags, const u16* filename,
                                            u32 handle, u32 len, void* data) {
  (void)flags;
  return ver_GetFileVersionInfoW(filename, handle, len, data);
}
int TRT_GUEST_ABI ver_VerQueryValueW(const void* block, const u16* subBlock,
                                     void** buffer, u32* len) {
  if (!block || !subBlock || !buffer || !len) return 0;
  const ver_block* b = (const ver_block*)block;
  // Root query L"\\" returns VS_FIXEDFILEINFO
  if ((subBlock[0] == '\\' && subBlock[1] == 0) || subBlock[0] == 0) {
    *buffer = (void*)&b->dwSignature;
    *len = 52;
    return 1;
  }
  *buffer = nullptr;
  *len = 0;
  return 0;
}
int TRT_GUEST_ABI ver_VerQueryValueA(const void* block, const char* subBlock,
                                     void** buffer, u32* len) {
  if (!block || !subBlock || !buffer || !len) return 0;
  const ver_block* b = (const ver_block*)block;
  if ((subBlock[0] == '\\' && subBlock[1] == 0) || subBlock[0] == 0) {
    *buffer = (void*)&b->dwSignature;
    *len = 52;
    return 1;
  }
  *buffer = nullptr;
  *len = 0;
  return 0;
}

// ============================================================================
// 6. winhttp.dll — Fail-visible offline HTTP surface
// ============================================================================

constexpr u32 ERROR_WINHTTP_CANNOT_CONNECT_ = 12029u;
constexpr u32 ERROR_WINHTTP_AUTODETECTION_FAILED_ = 12180u;

void* TRT_GUEST_ABI whttp_WinHttpOpen(const u16* agent, u32 accessType,
                                      const u16* proxy, const u16* bypass,
                                      u32 flags) {
  (void)agent; (void)accessType; (void)proxy; (void)bypass; (void)flags;
  log_line("winhttp: WinHttpOpen -> NULL (offline console environment)");
  trt_SetLastError(ERROR_WINHTTP_CANNOT_CONNECT_);
  return nullptr;
}
int TRT_GUEST_ABI whttp_WinHttpCloseHandle(void* hInternet) {
  (void)hInternet;
  return 1;
}
int TRT_GUEST_ABI whttp_WinHttpGetIEProxyConfigForCurrentUser(void* cfg) {
  if (cfg) memset(cfg, 0, 32);
  return 1;
}
int TRT_GUEST_ABI whttp_WinHttpGetProxyForUrl(void* hSession, const u16* url,
                                              const void* opts, void* info) {
  (void)hSession; (void)url; (void)opts; (void)info;
  trt_SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED_);
  return 0;
}
void* TRT_GUEST_ABI whttp_WinHttpConnect(void* hSession, const u16* server,
                                         u16 port, u32 reserved) {
  (void)hSession; (void)server; (void)port; (void)reserved;
  trt_SetLastError(ERROR_WINHTTP_CANNOT_CONNECT_);
  return nullptr;
}
void* TRT_GUEST_ABI whttp_WinHttpOpenRequest(void* hConnect, const u16* verb,
                                             const u16* objName,
                                             const u16* version,
                                             const u16* referrer,
                                             const u16** acceptTypes,
                                             u32 flags) {
  (void)hConnect; (void)verb; (void)objName; (void)version;
  (void)referrer; (void)acceptTypes; (void)flags;
  trt_SetLastError(ERROR_WINHTTP_CANNOT_CONNECT_);
  return nullptr;
}
int TRT_GUEST_ABI whttp_WinHttpSendRequest(void* hRequest, const u16* headers,
                                           u32 headersLen, void* optional,
                                           u32 optionalLen, u32 totalLen,
                                           u64 context) {
  (void)hRequest; (void)headers; (void)headersLen; (void)optional;
  (void)optionalLen; (void)totalLen; (void)context;
  trt_SetLastError(ERROR_WINHTTP_CANNOT_CONNECT_);
  return 0;
}
int TRT_GUEST_ABI whttp_WinHttpReceiveResponse(void* hRequest, void* reserved) {
  (void)hRequest; (void)reserved;
  trt_SetLastError(ERROR_WINHTTP_CANNOT_CONNECT_);
  return 0;
}
int TRT_GUEST_ABI whttp_WinHttpQueryDataAvailable(void* hRequest,
                                                  u32* bytesAvailable) {
  (void)hRequest;
  if (bytesAvailable) *bytesAvailable = 0;
  return 0;
}
int TRT_GUEST_ABI whttp_WinHttpReadData(void* hRequest, void* buffer,
                                        u32 toRead, u32* bytesRead) {
  (void)hRequest; (void)buffer; (void)toRead;
  if (bytesRead) *bytesRead = 0;
  return 0;
}
int TRT_GUEST_ABI whttp_WinHttpQueryHeaders(void* hRequest, u32 infoLevel,
                                            const u16* name, void* buffer,
                                            u32* bufLen, u32* index) {
  (void)hRequest; (void)infoLevel; (void)name; (void)buffer;
  (void)bufLen; (void)index;
  return 0;
}
int TRT_GUEST_ABI whttp_WinHttpSetOption(void* hInternet, u32 option,
                                         void* buffer, u32 bufLen) {
  (void)hInternet; (void)option; (void)buffer; (void)bufLen;
  return 1;
}
int TRT_GUEST_ABI whttp_WinHttpQueryOption(void* hInternet, u32 option,
                                           void* buffer, u32* bufLen) {
  (void)hInternet; (void)option; (void)buffer; (void)bufLen;
  return 0;
}
int TRT_GUEST_ABI whttp_WinHttpSetTimeouts(void* hInternet, int resolve,
                                           int connect, int send, int receive) {
  (void)hInternet; (void)resolve; (void)connect; (void)send; (void)receive;
  return 1;
}
int TRT_GUEST_ABI whttp_WinHttpCrackUrl(const u16* url, u32 urlLen, u32 flags,
                                        void* components) {
  (void)url; (void)urlLen; (void)flags; (void)components;
  return 0;
}

#if defined(_WIN32)
struct winrt_host_procs {
  using CreateStr_t = i32(__stdcall*)(const u16*, u32, void**);
  using CreateStrRef_t = i32(__stdcall*)(const u16*, u32, void*, void**);
  using DeleteStr_t = i32(__stdcall*)(void*);
  using DupStr_t = i32(__stdcall*)(void*, void**);
  using GetRaw_t = const u16*(__stdcall*)(void*, u32*);
  using GetLen_t = u32(__stdcall*)(void*);
  using IsEmpty_t = i32(__stdcall*)(void*);
  using CmpStr_t = i32(__stdcall*)(void*, void*, i32*);
  using ConcatStr_t = i32(__stdcall*)(void*, void*, void**);
  using RoInit_t = i32(__stdcall*)(u32);
  using RoUninit_t = void(__stdcall*)(void);
  using RoAct_t = i32(__stdcall*)(void*, void**);
  using RoFac_t = i32(__stdcall*)(void*, const void*, void**);

  CreateStr_t WindowsCreateString = nullptr;
  CreateStrRef_t WindowsCreateStringReference = nullptr;
  DeleteStr_t WindowsDeleteString = nullptr;
  DupStr_t WindowsDuplicateString = nullptr;
  GetRaw_t WindowsGetStringRawBuffer = nullptr;
  GetLen_t WindowsGetStringLen = nullptr;
  IsEmpty_t WindowsIsStringEmpty = nullptr;
  CmpStr_t WindowsCompareStringOrdinal = nullptr;
  ConcatStr_t WindowsConcatString = nullptr;
  RoInit_t RoInitialize = nullptr;
  RoUninit_t RoUninitialize = nullptr;
  RoAct_t RoActivateInstance = nullptr;
  RoFac_t RoGetActivationFactory = nullptr;
  bool str_ready = false;
  bool ro_ready = false;
};

static winrt_host_procs& winrt_procs() {
  static winrt_host_procs p;
  static std::once_flag once;
  std::call_once(once, [] {
    HMODULE combase = ::GetModuleHandleW(L"combase.dll");
    HMODULE str_mod = ::GetModuleHandleW(L"api-ms-win-core-winrt-string-l1-1-0.dll");
    HMODULE ro_mod = ::GetModuleHandleW(L"api-ms-win-core-winrt-l1-1-0.dll");
    auto lookup = [&](HMODULE pref, const char* sym) -> FARPROC {
      if (pref) {
        if (FARPROC f = ::GetProcAddress(pref, sym)) return f;
      }
      if (combase && pref != combase) return ::GetProcAddress(combase, sym);
      return nullptr;
    };
    p.WindowsCreateString = (winrt_host_procs::CreateStr_t)lookup(str_mod, "WindowsCreateString");
    p.WindowsCreateStringReference = (winrt_host_procs::CreateStrRef_t)lookup(str_mod, "WindowsCreateStringReference");
    p.WindowsDeleteString = (winrt_host_procs::DeleteStr_t)lookup(str_mod, "WindowsDeleteString");
    p.WindowsDuplicateString = (winrt_host_procs::DupStr_t)lookup(str_mod, "WindowsDuplicateString");
    p.WindowsGetStringRawBuffer = (winrt_host_procs::GetRaw_t)lookup(str_mod, "WindowsGetStringRawBuffer");
    p.WindowsGetStringLen = (winrt_host_procs::GetLen_t)lookup(str_mod, "WindowsGetStringLen");
    p.WindowsIsStringEmpty = (winrt_host_procs::IsEmpty_t)lookup(str_mod, "WindowsIsStringEmpty");
    p.WindowsCompareStringOrdinal = (winrt_host_procs::CmpStr_t)lookup(str_mod, "WindowsCompareStringOrdinal");
    p.WindowsConcatString = (winrt_host_procs::ConcatStr_t)lookup(str_mod, "WindowsConcatString");
    p.str_ready = (p.WindowsCreateString && p.WindowsCreateStringReference &&
                   p.WindowsDeleteString && p.WindowsGetStringRawBuffer &&
                   p.WindowsGetStringLen);

    p.RoInitialize = (winrt_host_procs::RoInit_t)lookup(ro_mod, "RoInitialize");
    p.RoUninitialize = (winrt_host_procs::RoUninit_t)lookup(ro_mod, "RoUninitialize");
    p.RoActivateInstance = (winrt_host_procs::RoAct_t)lookup(ro_mod, "RoActivateInstance");
    p.RoGetActivationFactory = (winrt_host_procs::RoFac_t)lookup(ro_mod, "RoGetActivationFactory");
    p.ro_ready = (p.str_ready && p.RoActivateInstance && p.RoGetActivationFactory);
  });
  return p;
}

i32 TRT_GUEST_ABI wrt_win32_WindowsCreateString(const u16* src, u32 len, void** out) {
  auto& p = winrt_procs();
  if (p.str_ready) return p.WindowsCreateString(src, len, out);
  return wrt_WindowsCreateString(src, len, out);
}
i32 TRT_GUEST_ABI wrt_win32_WindowsCreateStringReference(const u16* src, u32 len,
                                                       void* hdr, void** out) {
  auto& p = winrt_procs();
  if (p.str_ready) return p.WindowsCreateStringReference(src, len, hdr, out);
  return wrt_WindowsCreateStringReference(src, len, hdr, out);
}
i32 TRT_GUEST_ABI wrt_win32_WindowsDeleteString(void* s) {
  auto& p = winrt_procs();
  if (p.str_ready) return p.WindowsDeleteString(s);
  return wrt_WindowsDeleteString(s);
}
i32 TRT_GUEST_ABI wrt_win32_WindowsDuplicateString(void* s, void** out) {
  auto& p = winrt_procs();
  if (p.str_ready && p.WindowsDuplicateString) return p.WindowsDuplicateString(s, out);
  return wrt_WindowsDuplicateString(s, out);
}
const u16* TRT_GUEST_ABI wrt_win32_WindowsGetStringRawBuffer(void* s, u32* len) {
  auto& p = winrt_procs();
  if (p.str_ready) return p.WindowsGetStringRawBuffer(s, len);
  return wrt_WindowsGetStringRawBuffer(s, len);
}
u32 TRT_GUEST_ABI wrt_win32_WindowsGetStringLen(void* s) {
  auto& p = winrt_procs();
  if (p.str_ready) return p.WindowsGetStringLen(s);
  return wrt_WindowsGetStringLen(s);
}
i32 TRT_GUEST_ABI wrt_win32_WindowsIsStringEmpty(void* s) {
  auto& p = winrt_procs();
  if (p.str_ready && p.WindowsIsStringEmpty) return p.WindowsIsStringEmpty(s);
  return wrt_WindowsIsStringEmpty(s);
}
i32 TRT_GUEST_ABI wrt_win32_WindowsCompareStringOrdinal(void* s1, void* s2, i32* res) {
  auto& p = winrt_procs();
  if (p.str_ready && p.WindowsCompareStringOrdinal)
    return p.WindowsCompareStringOrdinal(s1, s2, res);
  return wrt_WindowsCompareStringOrdinal(s1, s2, res);
}
i32 TRT_GUEST_ABI wrt_win32_WindowsConcatString(void* s1, void* s2, void** out) {
  auto& p = winrt_procs();
  if (p.str_ready && p.WindowsConcatString) return p.WindowsConcatString(s1, s2, out);
  return wrt_WindowsConcatString(s1, s2, out);
}
i32 TRT_GUEST_ABI wrt_win32_RoInitialize(u32 init_type) {
  auto& p = winrt_procs();
  if (p.RoInitialize) return p.RoInitialize(init_type);
  return wrt_RoInitialize(init_type);
}
void TRT_GUEST_ABI wrt_win32_RoUninitialize(void) {
  auto& p = winrt_procs();
  if (p.RoUninitialize) { p.RoUninitialize(); return; }
  wrt_RoUninitialize();
}
static void wrt_format_class(void* id, char* cls, size_t cap) {
  u32 len = 0;
  const u16* raw = wrt_win32_WindowsGetStringRawBuffer(id, &len);
  size_t i = 0;
  if (raw) {
    for (; i < len && i + 1 < cap; ++i) cls[i] = (char)raw[i];
  }
  cls[i] = 0;
}
i32 TRT_GUEST_ABI wrt_win32_RoActivateInstance(void* id, void** inst) {
  auto& p = winrt_procs();
  const i32 hr =
      p.ro_ready ? p.RoActivateInstance(id, inst) : REGDB_E_CLASSNOTREG_;
  if (hr < 0) {
    char cls[96] = {};
    wrt_format_class(id, cls, sizeof(cls));
    if (wrt_offline_activate(cls, inst) >= 0) return S_OK_;
    char line[160];
    snprintf(line, sizeof(line),
             "winrt: host RoActivateInstance('%s') -> 0x%08x", cls, (u32)hr);
    log_line(line);
  }
  return hr;
}
i32 TRT_GUEST_ABI wrt_win32_RoGetActivationFactory(void* id, const void* iid,
                                                   void** fac) {
  auto& p = winrt_procs();
  const i32 hr = p.ro_ready ? p.RoGetActivationFactory(id, iid, fac)
                            : REGDB_E_CLASSNOTREG_;
  if (hr < 0) {
    char cls[96] = {};
    wrt_format_class(id, cls, sizeof(cls));
    const i32 off_hr = wrt_offline_factory(cls, iid, fac);
    if (off_hr != REGDB_E_CLASSNOTREG_) return off_hr;
    char line[160];
    snprintf(line, sizeof(line),
             "winrt: host RoGetActivationFactory('%s') -> 0x%08x", cls, (u32)hr);
    log_line(line);
  }
  return hr;
}
#endif

// ---- offline / fallback WinRT runtime classes ----
static constexpr i32 E_NOTIMPL_RT_ = (i32)0x80004001;
static constexpr i32 E_BOUNDS_RT_ = (i32)0x8000000B;

static i32 wrt_make_hstr(const char* s, void** out) {
  if (!out) return E_INVALIDARG_;
  u16 w[260];
  u32 n = 0;
  if (s) {
    while (s[n] && n + 1 < 260) {
      w[n] = (u16)(u8)s[n];
      ++n;
    }
  }
  w[n] = 0;
#if defined(_WIN32)
  return wrt_win32_WindowsCreateString(w, n, out);
#else
  return wrt_WindowsCreateString(w, n, out);
#endif
}

struct wrt_guid {
  u32 d1;
  u16 d2;
  u16 d3;
  u8 d4[8];
};
static_assert(sizeof(wrt_guid) == 16, "GUID must be 16 bytes");

static inline bool iid_eq(const void* a, const wrt_guid& b) {
  return a && memcmp(a, &b, 16) == 0;
}

static constexpr wrt_guid k_iid_unknown = {
    0x00000000, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static constexpr wrt_guid k_iid_inspectable = {
    0xaf86e2e0, 0xb12d, 0x4c6a, {0x9c, 0x5a, 0xd7, 0xaa, 0x65, 0x10, 0x1e, 0x90}};
static constexpr wrt_guid k_iid_agile = {
    0x94ea2b94, 0xe9cc, 0x49e0, {0xc0, 0xff, 0xee, 0x64, 0xca, 0x8f, 0x5b, 0x90}};
static constexpr wrt_guid k_iid_act_factory = {
    0x00000035, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};

static constexpr wrt_guid k_iid_gamepad = {
    0xbc7bb43c, 0x0a69, 0x3903, {0x9e, 0x9d, 0xa5, 0x0f, 0x86, 0xa4, 0x5d, 0xe5}};
static constexpr wrt_guid k_iid_gamepad2 = {
    0x3c1689bd, 0x5915, 0x4245, {0xb0, 0xc0, 0xc8, 0x9f, 0xae, 0x03, 0x08, 0xff}};
static constexpr wrt_guid k_iid_gamepad_statics = {
    0x8bbce529, 0xd49c, 0x39e9, {0x95, 0x60, 0xe4, 0x7d, 0xde, 0x96, 0xb7, 0xc8}};
static constexpr wrt_guid k_iid_gamepad_statics2 = {
    0x42676dc5, 0x0856, 0x47c4, {0x92, 0x13, 0xb3, 0x95, 0x50, 0x4c, 0x3a, 0x3c}};
static constexpr wrt_guid k_iid_raw_gc = {
    0x7cad6d91, 0xa7e1, 0x4f71, {0x9a, 0x78, 0x33, 0xe9, 0xc5, 0xdf, 0xea, 0x62}};
static constexpr wrt_guid k_iid_raw_gc_statics = {
    0xeb8d0792, 0xe95a, 0x4b19, {0xaf, 0xc7, 0x0a, 0x59, 0xf8, 0xbf, 0x75, 0x9e}};

static constexpr wrt_guid k_iid_dq = {
    0x603e88e4, 0xa338, 0x4ffe, {0xa4, 0x57, 0xa5, 0xcf, 0xb9, 0xce, 0xb8, 0x99}};
static constexpr wrt_guid k_iid_dq2 = {
    0xc822c647, 0x30ef, 0x506e, {0xbd, 0x1e, 0xa6, 0x47, 0xae, 0x66, 0x75, 0xff}};
static constexpr wrt_guid k_iid_dqc = {
    0x22f34e66, 0x50db, 0x4e36, {0xa9, 0x8d, 0x61, 0xc0, 0x1b, 0x38, 0x4d, 0x20}};
static constexpr wrt_guid k_iid_dqc_statics = {
    0x0a6c98e0, 0x5198, 0x49a2, {0xa3, 0x13, 0x3f, 0x70, 0xd1, 0xf1, 0x3c, 0x27}};
static constexpr wrt_guid k_iid_dq_statics = {
    0xa96d83d7, 0x9371, 0x4517, {0x92, 0x45, 0xd0, 0x82, 0x4a, 0xc1, 0x2c, 0x74}};

static constexpr wrt_guid k_iid_disp_info = {
    0xbed112ae, 0xadc3, 0x4dc9, {0xae, 0x65, 0x85, 0x1f, 0x4d, 0x7d, 0x47, 0x99}};
static constexpr wrt_guid k_iid_disp_info_statics = {
    0xc6a02a6c, 0xd452, 0x44dc, {0xba, 0x07, 0x96, 0xf3, 0xc6, 0xad, 0xf9, 0xd1}};

static constexpr wrt_guid k_iid_lang = {
    0xea79a752, 0xf7c2, 0x4265, {0xb1, 0xbd, 0xc4, 0xde, 0xc4, 0xe4, 0xf0, 0x80}};
static constexpr wrt_guid k_iid_lang_factory = {
    0x9b0252ac, 0x0c27, 0x44f8, {0xb7, 0x92, 0x97, 0x93, 0xfb, 0x66, 0xc6, 0x3e}};
static constexpr wrt_guid k_iid_lang_statics = {
    0xb23cd557, 0x0865, 0x46d4, {0x89, 0xb8, 0xd5, 0x9b, 0xe8, 0x99, 0x0f, 0x0d}};
static constexpr wrt_guid k_iid_app_langs_statics = {
    0x75b40847, 0x0a4c, 0x4a92, {0x95, 0x65, 0xfd, 0x63, 0xc9, 0x5f, 0x7a, 0xed}};

static constexpr wrt_guid k_iid_app_data = {
    0xc3da6fb7, 0xb744, 0x4b45, {0xb0, 0xb8, 0x22, 0x3a, 0x09, 0x38, 0xd0, 0xdc}};
static constexpr wrt_guid k_iid_app_data_statics = {
    0x5612147b, 0xe843, 0x45e3, {0x94, 0xd8, 0x06, 0x16, 0x9e, 0x3c, 0x8e, 0x17}};
static constexpr wrt_guid k_iid_storage_folder = {
    0x72d1cb78, 0xb3ef, 0x4f75, {0xa8, 0x0b, 0x6f, 0xd9, 0xda, 0xe2, 0x94, 0x4b}};
static constexpr wrt_guid k_iid_storage_item = {
    0x4207a996, 0xca2f, 0x42f7, {0xbd, 0xe8, 0x8b, 0x10, 0x45, 0x7a, 0x7f, 0x30}};

static bool is_base_iid(const void* iid) {
  return iid_eq(iid, k_iid_unknown) || iid_eq(iid, k_iid_inspectable) ||
         iid_eq(iid, k_iid_agile);
}

u32 TRT_GUEST_ABI wrt_singleton_AddRef(void*) { return 1; }
u32 TRT_GUEST_ABI wrt_singleton_Release(void*) { return 1; }
i32 TRT_GUEST_ABI wrt_common_GetIids(void*, u32* count, void** iids) {
  if (count) *count = 0;
  if (iids) *iids = nullptr;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_common_GetTrustLevel(void*, i32* trust) {
  if (trust) *trust = 0;
  return S_OK_;
}

// ---- 1. Windows.System.DispatcherQueueController ----
struct wrt_dq_obj;
struct wrt_dq_iface {
  const void* const* vtbl;
  wrt_dq_obj* owner;
};
struct wrt_dq_obj {
  wrt_dq_iface dq1;
  wrt_dq_iface dq2;
};
extern const void* const g_dq1_vtbl[13];
extern const void* const g_dq2_vtbl[7];
static wrt_dq_obj g_dq_obj = {{g_dq1_vtbl, &g_dq_obj}, {g_dq2_vtbl, &g_dq_obj}};

i32 TRT_GUEST_ABI wrt_dq_QI(void* self, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  auto* o = ((wrt_dq_iface*)self)->owner;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_dq)) {
    *out = &o->dq1;
    return S_OK_;
  }
  if (iid_eq(iid, k_iid_dq2)) {
    *out = &o->dq2;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_dq_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.System.DispatcherQueue", cls);
}
i32 TRT_GUEST_ABI wrt_dq_CreateTimer(void*, void** out) {
  if (out) *out = nullptr;
  return E_NOTIMPL_RT_;
}
i32 TRT_GUEST_ABI wrt_dq_TryEnqueue(void*, void*, u8* res) {
  if (res) *res = 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_dq_TryEnqueuePrio(void*, i32, void*, u8* res) {
  if (res) *res = 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_dq_AddEvt(void*, void*, i64* tok) {
  if (tok) *tok = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_dq_RemEvt(void*, i64) { return S_OK_; }
i32 TRT_GUEST_ABI wrt_dq_HasThreadAccess(void*, u8* val) {
  if (val) *val = 1;
  return S_OK_;
}
const void* const g_dq1_vtbl[13] = {
    (const void*)&wrt_dq_QI,          (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_dq_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_dq_CreateTimer,  (const void*)&wrt_dq_TryEnqueue,
    (const void*)&wrt_dq_TryEnqueuePrio, (const void*)&wrt_dq_AddEvt,
    (const void*)&wrt_dq_RemEvt,       (const void*)&wrt_dq_AddEvt,
    (const void*)&wrt_dq_RemEvt,
};
const void* const g_dq2_vtbl[7] = {
    (const void*)&wrt_dq_QI,          (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_dq_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_dq_HasThreadAccess,
};

struct wrt_dqc_obj {
  const void* const* vtbl;
};
extern const void* const g_dqc_vtbl[8];
static wrt_dqc_obj g_dqc_obj = {g_dqc_vtbl};
i32 TRT_GUEST_ABI wrt_dqc_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_dqc)) {
    *out = &g_dqc_obj;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_dqc_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.System.DispatcherQueueController", cls);
}
i32 TRT_GUEST_ABI wrt_dqc_get_DQ(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_dq_obj.dq1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_dqc_ShutdownAsync(void*, void** op) {
  if (op) *op = nullptr;
  return S_OK_;
}
const void* const g_dqc_vtbl[8] = {
    (const void*)&wrt_dqc_QI,          (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_dqc_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_dqc_get_DQ,      (const void*)&wrt_dqc_ShutdownAsync,
};

struct wrt_dqc_statics_obj {
  const void* const* vtbl;
};
extern const void* const g_dqc_statics_vtbl[7];
static wrt_dqc_statics_obj g_dqc_statics_obj = {g_dqc_statics_vtbl};
i32 TRT_GUEST_ABI wrt_dqcs_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_dqc_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_dqc_statics_obj;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_dqcs_CreateOnDedicatedThread(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_dqc_obj;
  return S_OK_;
}
const void* const g_dqc_statics_vtbl[7] = {
    (const void*)&wrt_dqcs_QI,          (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_dqc_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_dqcs_CreateOnDedicatedThread,
};

extern const void* const g_dq_statics_vtbl[7];
static wrt_dqc_statics_obj g_dq_statics_obj = {g_dq_statics_vtbl};
i32 TRT_GUEST_ABI wrt_dqs_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_dq_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_dq_statics_obj;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_dqs_GetForCurrentThread(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_dq_obj.dq1;
  return S_OK_;
}
const void* const g_dq_statics_vtbl[7] = {
    (const void*)&wrt_dqs_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_dq_GetClassName,  (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_dqs_GetForCurrentThread,
};

// ---- 2. Windows.Gaming.Input.Gamepad & RawGameController ----
struct wrt_gamepad_reading {
  u64 Timestamp;
  u32 Buttons;
  u32 pad_;
  double LeftTrigger;
  double RightTrigger;
  double LeftThumbstickX;
  double LeftThumbstickY;
  double RightThumbstickX;
  double RightThumbstickY;
};
struct wrt_gamepad_vibration {
  double LeftMotor;
  double RightMotor;
  double LeftTrigger;
  double RightTrigger;
};

struct wrt_gamepad_obj;
struct wrt_gamepad_iface {
  const void* const* vtbl;
  wrt_gamepad_obj* owner;
};
struct wrt_gamepad_obj {
  wrt_gamepad_iface gp1;
  wrt_gamepad_iface gp2;
  u32 index;
  double vib_l, vib_r, vib_lt, vib_rt;
};
extern const void* const g_gp1_vtbl[9];
extern const void* const g_gp2_vtbl[7];
static wrt_gamepad_obj g_gamepads[4] = {
    {{g_gp1_vtbl, &g_gamepads[0]}, {g_gp2_vtbl, &g_gamepads[0]}, 0, 0, 0, 0, 0},
    {{g_gp1_vtbl, &g_gamepads[1]}, {g_gp2_vtbl, &g_gamepads[1]}, 1, 0, 0, 0, 0},
    {{g_gp1_vtbl, &g_gamepads[2]}, {g_gp2_vtbl, &g_gamepads[2]}, 2, 0, 0, 0, 0},
    {{g_gp1_vtbl, &g_gamepads[3]}, {g_gp2_vtbl, &g_gamepads[3]}, 3, 0, 0, 0, 0},
};
static std::atomic<u64> g_wrt_pad_ts{1};

static double wrt_norm_axis(i16 v) {
  return v >= 0 ? (double)v / 32767.0 : (double)v / 32768.0;
}

i32 TRT_GUEST_ABI wrt_gp_QI(void* self, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  auto* o = ((wrt_gamepad_iface*)self)->owner;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_gamepad)) {
    *out = &o->gp1;
    return S_OK_;
  }
  if (iid_eq(iid, k_iid_gamepad2)) {
    *out = &o->gp2;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_gp_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Gaming.Input.Gamepad", cls);
}
i32 TRT_GUEST_ABI wrt_gp_get_Vibration(void* self, wrt_gamepad_vibration* v) {
  if (!v) return E_POINTER_;
  auto* o = ((wrt_gamepad_iface*)self)->owner;
  v->LeftMotor = o->vib_l;
  v->RightMotor = o->vib_r;
  v->LeftTrigger = o->vib_lt;
  v->RightTrigger = o->vib_rt;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gp_put_Vibration(void* self, wrt_gamepad_vibration v) {
  auto* o = ((wrt_gamepad_iface*)self)->owner;
  auto clamp01 = [](double x) -> double {
    return x < 0.0 ? 0.0 : (x > 1.0 ? 1.0 : x);
  };
  o->vib_l = clamp01(v.LeftMotor);
  o->vib_r = clamp01(v.RightMotor);
  o->vib_lt = clamp01(v.LeftTrigger);
  o->vib_rt = clamp01(v.RightTrigger);
  trt_pad_set_vibration(o->index, (u16)(o->vib_l * 65535.0),
                        (u16)(o->vib_r * 65535.0));
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gp_GetCurrentReading(void* self, wrt_gamepad_reading* r) {
  if (!r) return E_POINTER_;
  auto* o = ((wrt_gamepad_iface*)self)->owner;
  memset(r, 0, sizeof(*r));
  r->Timestamp = g_wrt_pad_ts.fetch_add(1, std::memory_order_relaxed);
  const u32 idx = o->index;
  if (!trt_pad_connected(idx)) return S_OK_;
  struct { u16 xbit; u32 rbit; } static constexpr k_map[] = {
      {0x0010, 0x1},    // Start -> Menu
      {0x0020, 0x2},    // Back -> View
      {0x1000, 0x4},    // A
      {0x2000, 0x8},    // B
      {0x4000, 0x10},   // X
      {0x8000, 0x20},   // Y
      {0x0001, 0x40},   // DPadUp
      {0x0002, 0x80},   // DPadDown
      {0x0004, 0x100},  // DPadLeft
      {0x0008, 0x200},  // DPadRight
      {0x0100, 0x400},  // LeftShoulder
      {0x0200, 0x800},  // RightShoulder
      {0x0040, 0x1000}, // LeftThumbstick
      {0x0080, 0x2000}, // RightThumbstick
  };
  u32 btns = 0;
  for (const auto& m : k_map) {
    if (trt_pad_down_n(idx, m.xbit)) btns |= m.rbit;
  }
  r->Buttons = btns;
  r->LeftTrigger = (double)trt_pad_trigger_n(idx, 0) / 255.0;
  r->RightTrigger = (double)trt_pad_trigger_n(idx, 1) / 255.0;
  r->LeftThumbstickX = wrt_norm_axis(trt_pad_thumb_n(idx, 0));
  r->LeftThumbstickY = wrt_norm_axis(trt_pad_thumb_n(idx, 1));
  r->RightThumbstickX = wrt_norm_axis(trt_pad_thumb_n(idx, 2));
  r->RightThumbstickY = wrt_norm_axis(trt_pad_thumb_n(idx, 3));
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gp_GetButtonLabel(void*, u32 btn, i32* label) {
  if (!label) return E_POINTER_;
  i32 v = 0;
  switch (btn) {
    case 0x4: v = 1; break;   // XboxA
    case 0x8: v = 2; break;   // XboxB
    case 0x10: v = 3; break;  // XboxX
    case 0x20: v = 4; break;  // XboxY
    case 0x40: v = 5; break;  // XboxUp
    case 0x80: v = 6; break;  // XboxDown
    case 0x100: v = 7; break; // XboxLeft
    case 0x200: v = 8; break; // XboxRight
    case 0x400: v = 9; break; // XboxLeftBumper
    case 0x800: v = 10; break;// XboxRightBumper
    case 0x1000: v = 11; break;// XboxLeftStickButton
    case 0x2000: v = 12; break;// XboxRightStickButton
    case 0x1: v = 13; break;  // XboxMenu
    case 0x2: v = 14; break;  // XboxView
    default: v = 0; break;
  }
  *label = v;
  return S_OK_;
}
const void* const g_gp1_vtbl[9] = {
    (const void*)&wrt_gp_QI,              (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,  (const void*)&wrt_common_GetIids,
    (const void*)&wrt_gp_GetClassName,    (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_gp_get_Vibration,   (const void*)&wrt_gp_put_Vibration,
    (const void*)&wrt_gp_GetCurrentReading,
};
const void* const g_gp2_vtbl[7] = {
    (const void*)&wrt_gp_QI,              (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,  (const void*)&wrt_common_GetIids,
    (const void*)&wrt_gp_GetClassName,    (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_gp_GetButtonLabel,
};

static u32 wrt_pad_connected_count(void) {
  u32 n = 0;
  for (u32 i = 0; i < 4; ++i) {
    if (trt_pad_connected(i)) ++n;
  }
  return n;
}
static i32 wrt_pad_nth_slot(u32 idx) {
  u32 seen = 0;
  for (u32 i = 0; i < 4; ++i) {
    if (trt_pad_connected(i)) {
      if (seen == idx) return (i32)i;
      ++seen;
    }
  }
  return -1;
}

struct wrt_vec_obj {
  const void* const* vtbl;
};
extern const void* const g_gp_vec_vtbl[10];
static wrt_vec_obj g_gp_vec = {g_gp_vec_vtbl};
i32 TRT_GUEST_ABI wrt_gpv_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  (void)iid;
  *out = &g_gp_vec;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gpv_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Foundation.Collections.IVectorView`1<Windows.Gaming.Input.Gamepad>", cls);
}
i32 TRT_GUEST_ABI wrt_gpv_GetAt(void*, u32 index, void** res) {
  if (!res) return E_POINTER_;
  *res = nullptr;
  const i32 slot = wrt_pad_nth_slot(index);
  if (slot < 0) return E_BOUNDS_RT_;
  *res = &g_gamepads[slot].gp1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gpv_get_Size(void*, u32* res) {
  if (!res) return E_POINTER_;
  *res = wrt_pad_connected_count();
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gpv_IndexOf(void*, void* val, u32* index, u8* found) {
  if (index) *index = 0;
  if (found) *found = 0;
  const u32 n = wrt_pad_connected_count();
  for (u32 i = 0; i < n; ++i) {
    const i32 slot = wrt_pad_nth_slot(i);
    if (slot >= 0 && val == &g_gamepads[slot].gp1) {
      if (index) *index = i;
      if (found) *found = 1;
      break;
    }
  }
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gpv_GetMany(void*, u32 start, u32 len, void** items, u32* actual) {
  if (!actual) return E_POINTER_;
  const u32 total = wrt_pad_connected_count();
  u32 copied = 0;
  for (u32 i = start; i < total && copied < len; ++i) {
    const i32 slot = wrt_pad_nth_slot(i);
    if (slot >= 0 && items) items[copied] = &g_gamepads[slot].gp1;
    ++copied;
  }
  *actual = copied;
  return S_OK_;
}
const void* const g_gp_vec_vtbl[10] = {
    (const void*)&wrt_gpv_QI,          (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_gpv_GetClassName,(const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_gpv_GetAt,       (const void*)&wrt_gpv_get_Size,
    (const void*)&wrt_gpv_IndexOf,     (const void*)&wrt_gpv_GetMany,
};

struct wrt_gp_statics_iface {
  const void* const* vtbl;
};
extern const void* const g_gp_statics1_vtbl[11];
extern const void* const g_gp_statics2_vtbl[7];
static wrt_gp_statics_iface g_gp_statics1 = {g_gp_statics1_vtbl};
static wrt_gp_statics_iface g_gp_statics2 = {g_gp_statics2_vtbl};
i32 TRT_GUEST_ABI wrt_gps_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_gamepad_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_gp_statics1;
    return S_OK_;
  }
  if (iid_eq(iid, k_iid_gamepad_statics2)) {
    *out = &g_gp_statics2;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_gps_AddEvt(void*, void*, i64* tok) {
  if (tok) *tok = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_gps_RemEvt(void*, i64) { return S_OK_; }
i32 TRT_GUEST_ABI wrt_gps_get_Gamepads(void*, void** vec) {
  if (!vec) return E_POINTER_;
  *vec = &g_gp_vec;
  return S_OK_;
}
// RawGameController definitions declared below so FromGameController can cross-map.
struct wrt_rawgc_obj {
  const void* const* vtbl;
  u32 index;
};
extern const void* const g_rawgc_vtbl[15];
static wrt_rawgc_obj g_rawgcs[4] = {
    {g_rawgc_vtbl, 0}, {g_rawgc_vtbl, 1}, {g_rawgc_vtbl, 2}, {g_rawgc_vtbl, 3},
};
i32 TRT_GUEST_ABI wrt_gps_FromGC(void*, void* gc, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  for (u32 i = 0; i < 4; ++i) {
    if (gc == &g_rawgcs[i] || gc == &g_gamepads[i].gp1) {
      *out = &g_gamepads[i].gp1;
      break;
    }
  }
  return S_OK_;
}
const void* const g_gp_statics1_vtbl[11] = {
    (const void*)&wrt_gps_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_gp_GetClassName,  (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_gps_AddEvt,       (const void*)&wrt_gps_RemEvt,
    (const void*)&wrt_gps_AddEvt,       (const void*)&wrt_gps_RemEvt,
    (const void*)&wrt_gps_get_Gamepads,
};
const void* const g_gp_statics2_vtbl[7] = {
    (const void*)&wrt_gps_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_gp_GetClassName,  (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_gps_FromGC,
};

// RawGameController
i32 TRT_GUEST_ABI wrt_rawgc_QI(void* self, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_raw_gc)) {
    *out = self;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_rawgc_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Gaming.Input.RawGameController", cls);
}
i32 TRT_GUEST_ABI wrt_rawgc_get_AxisCount(void*, i32* v) {
  if (v) *v = 6;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_get_ButtonCount(void*, i32* v) {
  if (v) *v = 10;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_get_FFB(void*, void** v) {
  if (v) *v = nullptr;
  return E_NOTIMPL_RT_;
}
i32 TRT_GUEST_ABI wrt_rawgc_get_PID(void*, u16* v) {
  if (v) *v = 0x02ea;  // Xbox One S Wireless Controller PID
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_get_VID(void*, u16* v) {
  if (v) *v = 0x045e;  // Microsoft VID
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_get_SwitchCount(void*, i32* v) {
  if (v) *v = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_GetButtonLabel(void*, i32 btn, i32* label) {
  if (!label) return E_POINTER_;
  static constexpr i32 k_lbls[10] = {1, 2, 3, 4, 9, 10, 14, 13, 11, 12};
  *label = (btn >= 0 && btn < 10) ? k_lbls[btn] : 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_GetCurrentReading(void* self, u32 btn_len, u8* btns,
                                              u32 sw_len, i32* sw, u32 ax_len,
                                              double* ax, u64* ts) {
  auto* o = (wrt_rawgc_obj*)self;
  const u32 idx = o->index;
  if (ts) *ts = g_wrt_pad_ts.fetch_add(1, std::memory_order_relaxed);
  static constexpr u16 k_xbtns[10] = {0x1000, 0x2000, 0x4000, 0x8000, 0x0100,
                                      0x0200, 0x0020, 0x0010, 0x0040, 0x0080};
  const bool conn = trt_pad_connected(idx);
  if (btns) {
    for (u32 i = 0; i < btn_len; ++i) {
      btns[i] = (conn && i < 10 && trt_pad_down_n(idx, k_xbtns[i])) ? 1 : 0;
    }
  }
  if (sw && sw_len > 0) {
    if (!conn) {
      for (u32 i = 0; i < sw_len; ++i) sw[i] = 0;
    } else {
      const bool u = trt_pad_down_n(idx, 0x0001);
      const bool d = trt_pad_down_n(idx, 0x0002);
      const bool l = trt_pad_down_n(idx, 0x0004);
      const bool r = trt_pad_down_n(idx, 0x0008);
      i32 pos = 0;
      if (u && r) pos = 2;
      else if (d && r) pos = 4;
      else if (d && l) pos = 6;
      else if (u && l) pos = 8;
      else if (u) pos = 1;
      else if (r) pos = 3;
      else if (d) pos = 5;
      else if (l) pos = 7;
      sw[0] = pos;
      for (u32 i = 1; i < sw_len; ++i) sw[i] = 0;
    }
  }
  if (ax) {
    for (u32 i = 0; i < ax_len; ++i) {
      double v = (i < 4) ? 0.5 : 0.0;
      if (conn) {
        if (i < 4) v = (wrt_norm_axis(trt_pad_thumb_n(idx, (int)i)) + 1.0) * 0.5;
        else if (i == 4) v = (double)trt_pad_trigger_n(idx, 0) / 255.0;
        else if (i == 5) v = (double)trt_pad_trigger_n(idx, 1) / 255.0;
      }
      ax[i] = v;
    }
  }
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rawgc_GetSwitchKind(void*, i32, i32* kind) {
  if (kind) *kind = 1;  // EightWay
  return S_OK_;
}
const void* const g_rawgc_vtbl[15] = {
    (const void*)&wrt_rawgc_QI,              (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,     (const void*)&wrt_common_GetIids,
    (const void*)&wrt_rawgc_GetClassName,    (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_rawgc_get_AxisCount,   (const void*)&wrt_rawgc_get_ButtonCount,
    (const void*)&wrt_rawgc_get_FFB,         (const void*)&wrt_rawgc_get_PID,
    (const void*)&wrt_rawgc_get_VID,         (const void*)&wrt_rawgc_get_SwitchCount,
    (const void*)&wrt_rawgc_GetButtonLabel,  (const void*)&wrt_rawgc_GetCurrentReading,
    (const void*)&wrt_rawgc_GetSwitchKind,
};

extern const void* const g_rawgc_vec_vtbl[10];
static wrt_vec_obj g_rawgc_vec = {g_rawgc_vec_vtbl};
i32 TRT_GUEST_ABI wrt_rgcv_QI(void*, const void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_rawgc_vec;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rgcv_GetAt(void*, u32 index, void** res) {
  if (!res) return E_POINTER_;
  *res = nullptr;
  const i32 slot = wrt_pad_nth_slot(index);
  if (slot < 0) return E_BOUNDS_RT_;
  *res = &g_rawgcs[slot];
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rgcv_IndexOf(void*, void* val, u32* index, u8* found) {
  if (index) *index = 0;
  if (found) *found = 0;
  const u32 n = wrt_pad_connected_count();
  for (u32 i = 0; i < n; ++i) {
    const i32 slot = wrt_pad_nth_slot(i);
    if (slot >= 0 && val == &g_rawgcs[slot]) {
      if (index) *index = i;
      if (found) *found = 1;
      break;
    }
  }
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rgcv_GetMany(void*, u32 start, u32 len, void** items, u32* actual) {
  if (!actual) return E_POINTER_;
  const u32 total = wrt_pad_connected_count();
  u32 copied = 0;
  for (u32 i = start; i < total && copied < len; ++i) {
    const i32 slot = wrt_pad_nth_slot(i);
    if (slot >= 0 && items) items[copied] = &g_rawgcs[slot];
    ++copied;
  }
  *actual = copied;
  return S_OK_;
}
const void* const g_rawgc_vec_vtbl[10] = {
    (const void*)&wrt_rgcv_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_gpv_GetClassName,  (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_rgcv_GetAt,        (const void*)&wrt_gpv_get_Size,
    (const void*)&wrt_rgcv_IndexOf,      (const void*)&wrt_rgcv_GetMany,
};

extern const void* const g_rawgc_statics_vtbl[12];
static wrt_vec_obj g_rawgc_statics = {g_rawgc_statics_vtbl};
i32 TRT_GUEST_ABI wrt_rgcs_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_raw_gc_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_rawgc_statics;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_rgcs_get_RawGCs(void*, void** vec) {
  if (!vec) return E_POINTER_;
  *vec = &g_rawgc_vec;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_rgcs_FromGC(void*, void* gc, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  for (u32 i = 0; i < 4; ++i) {
    if (gc == &g_rawgcs[i] || gc == &g_gamepads[i].gp1) {
      *out = &g_rawgcs[i];
      break;
    }
  }
  return S_OK_;
}
const void* const g_rawgc_statics_vtbl[12] = {
    (const void*)&wrt_rgcs_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wrt_rawgc_GetClassName,(const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_gps_AddEvt,        (const void*)&wrt_gps_RemEvt,
    (const void*)&wrt_gps_AddEvt,        (const void*)&wrt_gps_RemEvt,
    (const void*)&wrt_rgcs_get_RawGCs,   (const void*)&wrt_rgcs_FromGC,
};

// ---- 3. Windows.Graphics.Display.DisplayInformation ----
extern const void* const g_disp_vtbl[22];
static wrt_vec_obj g_disp_obj = {g_disp_vtbl};
i32 TRT_GUEST_ABI wrt_disp_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_disp_info)) {
    *out = &g_disp_obj;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_disp_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Graphics.Display.DisplayInformation", cls);
}
i32 TRT_GUEST_ABI wrt_disp_get_Orient(void*, i32* v) {
  if (v) *v = 1;  // DisplayOrientations_Landscape
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_disp_get_Scale(void*, i32* v) {
  if (v) *v = 100;  // ResolutionScale_Scale100Percent
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_disp_get_Dpi(void*, float* v) {
  if (v) *v = 96.0f;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_disp_get_Stereo(void*, u8* v) {
  if (v) *v = 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_disp_GetColorAsync(void*, void** op) {
  if (op) *op = nullptr;
  return E_NOTIMPL_RT_;
}
const void* const g_disp_vtbl[22] = {
    (const void*)&wrt_disp_QI,            (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,  (const void*)&wrt_common_GetIids,
    (const void*)&wrt_disp_GetClassName,  (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_disp_get_Orient,    (const void*)&wrt_disp_get_Orient,
    (const void*)&wrt_gps_AddEvt,         (const void*)&wrt_gps_RemEvt,
    (const void*)&wrt_disp_get_Scale,     (const void*)&wrt_disp_get_Dpi,
    (const void*)&wrt_disp_get_Dpi,       (const void*)&wrt_disp_get_Dpi,
    (const void*)&wrt_gps_AddEvt,         (const void*)&wrt_gps_RemEvt,
    (const void*)&wrt_disp_get_Stereo,    (const void*)&wrt_gps_AddEvt,
    (const void*)&wrt_gps_RemEvt,         (const void*)&wrt_disp_GetColorAsync,
    (const void*)&wrt_gps_AddEvt,         (const void*)&wrt_gps_RemEvt,
};

extern const void* const g_disp_statics_vtbl[11];
static wrt_vec_obj g_disp_statics = {g_disp_statics_vtbl};
i32 TRT_GUEST_ABI wrt_disps_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_disp_info_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_disp_statics;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_disps_GetForCurrentView(void*, void** cur) {
  if (!cur) return E_POINTER_;
  *cur = &g_disp_obj;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_disps_put_AutoRot(void*, i32) { return S_OK_; }
const void* const g_disp_statics_vtbl[11] = {
    (const void*)&wrt_disps_QI,                 (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,        (const void*)&wrt_common_GetIids,
    (const void*)&wrt_disp_GetClassName,        (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_disps_GetForCurrentView,  (const void*)&wrt_disp_get_Orient,
    (const void*)&wrt_disps_put_AutoRot,        (const void*)&wrt_gps_AddEvt,
    (const void*)&wrt_gps_RemEvt,
};

// ---- 4. Windows.Globalization.Language & ApplicationLanguages ----
struct wrt_lang_obj {
  const void* const* vtbl;
  std::atomic<u32> refcount;
  char tag[64];
};
extern const void* const g_lang_vtbl[10];
i32 TRT_GUEST_ABI wrt_lang_QI(void* self, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_lang)) {
    *out = self;
    ((wrt_lang_obj*)self)->refcount.fetch_add(1, std::memory_order_relaxed);
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
u32 TRT_GUEST_ABI wrt_lang_AddRef(void* self) {
  return ((wrt_lang_obj*)self)->refcount.fetch_add(1, std::memory_order_relaxed) + 1;
}
u32 TRT_GUEST_ABI wrt_lang_Release(void* self) {
  auto* o = (wrt_lang_obj*)self;
  const u32 r = o->refcount.fetch_sub(1, std::memory_order_acq_rel) - 1;
  if (r == 0) delete o;
  return r;
}
i32 TRT_GUEST_ABI wrt_lang_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Globalization.Language", cls);
}
i32 TRT_GUEST_ABI wrt_lang_get_Tag(void* self, void** hstr) {
  return wrt_make_hstr(((wrt_lang_obj*)self)->tag, hstr);
}
i32 TRT_GUEST_ABI wrt_lang_get_Display(void*, void** hstr) {
  return wrt_make_hstr("English (United States)", hstr);
}
i32 TRT_GUEST_ABI wrt_lang_get_Script(void*, void** hstr) {
  return wrt_make_hstr("Latn", hstr);
}
const void* const g_lang_vtbl[10] = {
    (const void*)&wrt_lang_QI,          (const void*)&wrt_lang_AddRef,
    (const void*)&wrt_lang_Release,     (const void*)&wrt_common_GetIids,
    (const void*)&wrt_lang_GetClassName,(const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_lang_get_Tag,     (const void*)&wrt_lang_get_Display,
    (const void*)&wrt_lang_get_Display, (const void*)&wrt_lang_get_Script,
};

extern const void* const g_lang_fac_vtbl[7];
extern const void* const g_lang_sta_vtbl[8];
static wrt_vec_obj g_lang_fac = {g_lang_fac_vtbl};
static wrt_vec_obj g_lang_sta = {g_lang_sta_vtbl};
i32 TRT_GUEST_ABI wrt_langf_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_lang_factory) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_lang_fac;
    return S_OK_;
  }
  if (iid_eq(iid, k_iid_lang_statics)) {
    *out = &g_lang_sta;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_langf_Create(void*, void* tag_hstr, void** out) {
  if (!out) return E_POINTER_;
  auto* o = new wrt_lang_obj{};
  o->vtbl = g_lang_vtbl;
  o->refcount.store(1, std::memory_order_relaxed);
#if defined(_WIN32)
  wrt_format_class(tag_hstr, o->tag, sizeof(o->tag));
#else
  u32 len = 0;
  const u16* raw = wrt_WindowsGetStringRawBuffer(tag_hstr, &len);
  u32 i = 0;
  if (raw) {
    for (; i < len && i + 1 < sizeof(o->tag); ++i) o->tag[i] = (char)raw[i];
  }
  o->tag[i] = 0;
#endif
  if (o->tag[0] == 0) memcpy(o->tag, "en-US", 6);
  *out = o;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_langs_IsWellFormed(void*, void*, u8* res) {
  if (res) *res = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_langs_get_InputTag(void*, void** hstr) {
  return wrt_make_hstr("en-US", hstr);
}
const void* const g_lang_fac_vtbl[7] = {
    (const void*)&wrt_langf_QI,         (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_lang_GetClassName,(const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_langf_Create,
};
const void* const g_lang_sta_vtbl[8] = {
    (const void*)&wrt_langf_QI,         (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_lang_GetClassName,(const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_langs_IsWellFormed,(const void*)&wrt_langs_get_InputTag,
};

extern const void* const g_hstr_vec_vtbl[10];
static wrt_vec_obj g_hstr_vec = {g_hstr_vec_vtbl};
i32 TRT_GUEST_ABI wrt_hv_QI(void*, const void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_hstr_vec;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_hv_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Foundation.Collections.IVectorView`1<String>", cls);
}
i32 TRT_GUEST_ABI wrt_hv_GetAt(void*, u32 index, void** hstr) {
  if (index != 0) return E_BOUNDS_RT_;
  return wrt_make_hstr("en-US", hstr);
}
i32 TRT_GUEST_ABI wrt_hv_get_Size(void*, u32* sz) {
  if (sz) *sz = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_hv_IndexOf(void*, void*, u32* idx, u8* found) {
  if (idx) *idx = 0;
  if (found) *found = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_hv_GetMany(void*, u32 start, u32 len, void** items, u32* actual) {
  if (!actual) return E_POINTER_;
  if (start == 0 && len > 0 && items) {
    wrt_make_hstr("en-US", &items[0]);
    *actual = 1;
  } else {
    *actual = 0;
  }
  return S_OK_;
}
const void* const g_hstr_vec_vtbl[10] = {
    (const void*)&wrt_hv_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_hv_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_hv_GetAt,        (const void*)&wrt_hv_get_Size,
    (const void*)&wrt_hv_IndexOf,      (const void*)&wrt_hv_GetMany,
};

extern const void* const g_applangs_vtbl[10];
static wrt_vec_obj g_applangs_statics = {g_applangs_vtbl};
i32 TRT_GUEST_ABI wrt_al_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_app_langs_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_applangs_statics;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_al_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Globalization.ApplicationLanguages", cls);
}
i32 TRT_GUEST_ABI wrt_al_get_Primary(void*, void** hstr) {
  return wrt_make_hstr("", hstr);
}
i32 TRT_GUEST_ABI wrt_al_put_Primary(void*, void*) { return S_OK_; }
i32 TRT_GUEST_ABI wrt_al_get_Languages(void*, void** vec) {
  if (!vec) return E_POINTER_;
  *vec = &g_hstr_vec;
  return S_OK_;
}
const void* const g_applangs_vtbl[10] = {
    (const void*)&wrt_al_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_al_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_al_get_Primary,  (const void*)&wrt_al_put_Primary,
    (const void*)&wrt_al_get_Languages,(const void*)&wrt_al_get_Languages,
};

// ---- 5. Windows.Storage.ApplicationData & StorageFolder ----
struct wrt_folder_obj;
struct wrt_folder_iface {
  const void* const* vtbl;
  wrt_folder_obj* owner;
};
struct wrt_folder_obj {
  wrt_folder_iface folder;
  wrt_folder_iface item;
  const char* name;
  const char* path;
};
extern const void* const g_folder_vtbl[16];
extern const void* const g_item_vtbl[16];
static wrt_folder_obj g_local_folder = {
    {g_folder_vtbl, &g_local_folder},
    {g_item_vtbl, &g_local_folder},
    "LocalState",
    "C:\\tiramisu\\appdata\\local",
};
static wrt_folder_obj g_roaming_folder = {
    {g_folder_vtbl, &g_roaming_folder},
    {g_item_vtbl, &g_roaming_folder},
    "RoamingState",
    "C:\\tiramisu\\appdata\\roaming",
};
static wrt_folder_obj g_temp_folder = {
    {g_folder_vtbl, &g_temp_folder},
    {g_item_vtbl, &g_temp_folder},
    "TempState",
    "C:\\tiramisu\\appdata\\temp",
};

i32 TRT_GUEST_ABI wrt_fld_QI(void* self, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  auto* o = ((wrt_folder_iface*)self)->owner;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_storage_folder)) {
    *out = &o->folder;
    return S_OK_;
  }
  if (iid_eq(iid, k_iid_storage_item)) {
    *out = &o->item;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_fld_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Storage.StorageFolder", cls);
}
i32 TRT_GUEST_ABI wrt_fld_StubOp(void*, void*, void** op) {
  if (op) *op = nullptr;
  return E_NOTIMPL_RT_;
}
i32 TRT_GUEST_ABI wrt_fld_StubOp3(void*, void*, i32, void** op) {
  if (op) *op = nullptr;
  return E_NOTIMPL_RT_;
}
i32 TRT_GUEST_ABI wrt_fld_StubOp1(void*, void** op) {
  if (op) *op = nullptr;
  return E_NOTIMPL_RT_;
}
i32 TRT_GUEST_ABI wrt_itm_get_Name(void* self, void** hstr) {
  return wrt_make_hstr(((wrt_folder_iface*)self)->owner->name, hstr);
}
i32 TRT_GUEST_ABI wrt_itm_get_Path(void* self, void** hstr) {
  return wrt_make_hstr(((wrt_folder_iface*)self)->owner->path, hstr);
}
i32 TRT_GUEST_ABI wrt_itm_get_Attr(void*, u32* attr) {
  if (attr) *attr = 0x10;  // FileAttributes_Directory
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_itm_get_Date(void*, i64* dt) {
  if (dt) *dt = 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_itm_IsOfType(void*, i32 type, u8* res) {
  if (res) *res = (type == 2) ? 1 : 0;  // StorageItemTypes_Folder = 2
  return S_OK_;
}
const void* const g_folder_vtbl[16] = {
    (const void*)&wrt_fld_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_fld_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_fld_StubOp,       (const void*)&wrt_fld_StubOp3,
    (const void*)&wrt_fld_StubOp,       (const void*)&wrt_fld_StubOp3,
    (const void*)&wrt_fld_StubOp,       (const void*)&wrt_fld_StubOp,
    (const void*)&wrt_fld_StubOp,       (const void*)&wrt_fld_StubOp1,
    (const void*)&wrt_fld_StubOp1,      (const void*)&wrt_fld_StubOp1,
};
const void* const g_item_vtbl[16] = {
    (const void*)&wrt_fld_QI,           (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,(const void*)&wrt_common_GetIids,
    (const void*)&wrt_fld_GetClassName, (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_fld_StubOp,       (const void*)&wrt_fld_StubOp3,
    (const void*)&wrt_fld_StubOp1,      (const void*)&wrt_fld_StubOp,
    (const void*)&wrt_fld_StubOp1,      (const void*)&wrt_itm_get_Name,
    (const void*)&wrt_itm_get_Path,     (const void*)&wrt_itm_get_Attr,
    (const void*)&wrt_itm_get_Date,     (const void*)&wrt_itm_IsOfType,
};

extern const void* const g_appdata_vtbl[19];
static wrt_vec_obj g_appdata_obj = {g_appdata_vtbl};
i32 TRT_GUEST_ABI wrt_ad_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_app_data)) {
    *out = &g_appdata_obj;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_ad_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Storage.ApplicationData", cls);
}
i32 TRT_GUEST_ABI wrt_ad_get_Version(void*, u32* v) {
  if (v) *v = 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_ad_NullPtr(void*, void** out) {
  if (out) *out = nullptr;
  return E_NOTIMPL_RT_;
}
i32 TRT_GUEST_ABI wrt_ad_get_LocalFolder(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_local_folder.folder;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_ad_get_RoamingFolder(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_roaming_folder.folder;
  return S_OK_;
}
i32 TRT_GUEST_ABI wrt_ad_get_TempFolder(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_temp_folder.folder;
  return S_OK_;
}
void TRT_GUEST_ABI wrt_ad_Signal(void*) {}
i32 TRT_GUEST_ABI wrt_ad_get_Quota(void*, u64* q) {
  if (q) *q = 0;
  return S_OK_;
}
const void* const g_appdata_vtbl[19] = {
    (const void*)&wrt_ad_QI,               (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,   (const void*)&wrt_common_GetIids,
    (const void*)&wrt_ad_GetClassName,     (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_ad_get_Version,      (const void*)&wrt_fld_StubOp3,
    (const void*)&wrt_fld_StubOp1,         (const void*)&wrt_fld_StubOp,
    (const void*)&wrt_ad_NullPtr,          (const void*)&wrt_ad_NullPtr,
    (const void*)&wrt_ad_get_LocalFolder,  (const void*)&wrt_ad_get_RoamingFolder,
    (const void*)&wrt_ad_get_TempFolder,   (const void*)&wrt_gps_AddEvt,
    (const void*)&wrt_gps_RemEvt,          (const void*)&wrt_ad_Signal,
    (const void*)&wrt_ad_get_Quota,
};

extern const void* const g_appdatas_vtbl[7];
static wrt_vec_obj g_appdata_statics = {g_appdatas_vtbl};
i32 TRT_GUEST_ABI wrt_ads_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_app_data_statics) ||
      iid_eq(iid, k_iid_act_factory)) {
    *out = &g_appdata_statics;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wrt_ads_get_Current(void*, void** out) {
  if (!out) return E_POINTER_;
  *out = &g_appdata_obj;
  return S_OK_;
}
const void* const g_appdatas_vtbl[7] = {
    (const void*)&wrt_ads_QI,              (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release,   (const void*)&wrt_common_GetIids,
    (const void*)&wrt_ad_GetClassName,     (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wrt_ads_get_Current,
};

// ---- Dispatchers ----
// ---- Windows.System.Threading.ThreadPool (IThreadPoolStatics) --------------
// IIDs verified against mingw-w64 windows.system.threading.h (IThreadPoolStatics
// b6bf67dd-84bd-44f8-ac1c-93ebcb9dba91; WorkItemHandler delegate
// 1d1a8b8b-fa66-414f-9cbd-b65fc99d17fa invokes at vtbl slot 3),
// asyncinfo.h (IAsyncInfo 00000036-...) and windows.foundation.h
// (IAsyncAction 5a648006-...). Work items run on a detached host thread; the
// returned IAsyncAction reports Completed immediately (AsyncStatus::Completed=1).
static constexpr wrt_guid k_iid_wtp_statics = {
    0xb6bf67dd, 0x84bd, 0x44f8, {0xac, 0x1c, 0x93, 0xeb, 0xcb, 0x9d, 0xba, 0x91}};
static constexpr wrt_guid k_iid_async_info = {
    0x00000036, 0x0000, 0x0000, {0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}};
static constexpr wrt_guid k_iid_async_action = {
    0x5a648006, 0x843a, 0x4da9, {0x86, 0x5b, 0x9d, 0x26, 0xe5, 0xdf, 0xad, 0x7b}};

struct wrt_wtp_iface {
  const void* const* vtbl;
};

extern const void* const g_wtp_action_vtbl[14];
extern const void* const g_wtp_statics_vtbl[9];
static struct {
  const void* const* vtbl;
} g_wtp_action = {g_wtp_action_vtbl};
static wrt_wtp_iface g_wtp_statics = {g_wtp_statics_vtbl};

i32 TRT_GUEST_ABI wtp_act_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.Foundation.IAsyncAction", cls);
}
i32 TRT_GUEST_ABI wtp_act_qi(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_async_info) ||
      iid_eq(iid, k_iid_async_action)) {
    *out = &g_wtp_action;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wtp_act_get_id(void*, i32* out) {
  if (out) *out = 1;
  return S_OK_;
}
i32 TRT_GUEST_ABI wtp_act_get_status(void*, u32* out) {
  if (out) *out = 1;  // AsyncStatus::Completed
  return S_OK_;
}
i32 TRT_GUEST_ABI wtp_act_get_error(void*, i32* out) {
  if (out) *out = 0;
  return S_OK_;
}
i32 TRT_GUEST_ABI wtp_act_cancel(void*) { return S_OK_; }  // already completed
i32 TRT_GUEST_ABI wtp_act_close(void*) { return S_OK_; }
i32 TRT_GUEST_ABI wtp_act_put_completed(void*, void*) { return S_OK_; }
i32 TRT_GUEST_ABI wtp_act_get_completed(void*, void** out) {
  if (out) *out = nullptr;
  return S_OK_;
}
i32 TRT_GUEST_ABI wtp_act_get_results(void*, void** out) {
  if (out) *out = nullptr;
  return S_OK_;
}

const void* const g_wtp_action_vtbl[14] = {
    (const void*)&wtp_act_qi,            (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wtp_act_GetClassName,  (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wtp_act_get_id,        // 6  IAsyncInfo::get_Id
    (const void*)&wtp_act_get_status,    // 7  IAsyncInfo::get_Status
    (const void*)&wtp_act_get_error,     // 8  IAsyncInfo::get_ErrorCode
    (const void*)&wtp_act_cancel,        // 9  IAsyncInfo::Cancel
    (const void*)&wtp_act_close,         // 10 IAsyncInfo::Close
    (const void*)&wtp_act_put_completed, // 11 IAsyncAction::put_Completed
    (const void*)&wtp_act_get_completed, // 12 IAsyncAction::get_Completed
    (const void*)&wtp_act_get_results,   // 13 IAsyncAction::GetResults
};

// Invoke the WorkItemHandler (slot 3: Invoke(IAsyncAction*)) off the guest
// thread. Handler may be released by the caller after RunAsync returns, so
// copy the vtbl+object pointers before detaching.
static void wtp_run_handler_detached(void* handler) {
  struct job {
    void* h;
    const void* const* vtbl;
  };
  auto* j = new job{handler, handler ? *(const void* const**)handler : nullptr};
  std::thread([j] {
    if (j->vtbl && j->h) {
      using invoke_fn = i32 (TRT_GUEST_ABI*)(void*, void*);
      ((invoke_fn)j->vtbl[3])(j->h, &g_wtp_action);
    }
    delete j;
  }).detach();
}

i32 TRT_GUEST_ABI wtp_RunAsync(void*, void* handler, void** out_action) {
  if (!out_action) return E_POINTER_;
  *out_action = &g_wtp_action;
  static std::atomic<bool> logged{false};
  if (!logged.exchange(true))
    trt_core_log(
        "winrt: ThreadPool.RunAsync -> detached host thread + completed "
        "IAsyncAction");
  wtp_run_handler_detached(handler);
  return S_OK_;
}
i32 TRT_GUEST_ABI wtp_RunWithPriorityAsync(void*, void* handler, u32, void** out_action) {
  return wtp_RunAsync(nullptr, handler, out_action);
}
i32 TRT_GUEST_ABI wtp_RunWithPriorityAndOptionsAsync(void*, void* handler, u32, u32,
                                                     void** out_action) {
  return wtp_RunAsync(nullptr, handler, out_action);
}

i32 TRT_GUEST_ABI wtp_QI(void*, const void* iid, void** out) {
  if (!out) return E_POINTER_;
  *out = nullptr;
  if (is_base_iid(iid) || iid_eq(iid, k_iid_act_factory) ||
      iid_eq(iid, k_iid_wtp_statics)) {
    *out = &g_wtp_statics;
    return S_OK_;
  }
  return E_NOINTERFACE_;
}
i32 TRT_GUEST_ABI wtp_GetClassName(void*, void** cls) {
  return wrt_make_hstr("Windows.System.Threading.ThreadPool", cls);
}

const void* const g_wtp_statics_vtbl[9] = {
    (const void*)&wtp_QI,                (const void*)&wrt_singleton_AddRef,
    (const void*)&wrt_singleton_Release, (const void*)&wrt_common_GetIids,
    (const void*)&wtp_GetClassName,      (const void*)&wrt_common_GetTrustLevel,
    (const void*)&wtp_RunAsync,          // 6 RunAsync
    (const void*)&wtp_RunWithPriorityAsync, // 7 RunWithPriorityAsync
    (const void*)&wtp_RunWithPriorityAndOptionsAsync, // 8 RunWithPriorityAndOptionsAsync
};

static i32 wrt_offline_activate(const char* cls, void** instance) {
  if (!cls || !instance) return REGDB_E_CLASSNOTREG_;
  if (strcmp(cls, "Windows.Globalization.Language") == 0) {
    auto* o = new wrt_lang_obj{};
    o->vtbl = g_lang_vtbl;
    o->refcount.store(1, std::memory_order_relaxed);
    memcpy(o->tag, "en-US", 6);
    *instance = o;
    return S_OK_;
  }
  return REGDB_E_CLASSNOTREG_;
}

static i32 wrt_offline_factory(const char* cls, const void* iid, void** factory) {
  if (!cls || !factory) return REGDB_E_CLASSNOTREG_;
  void* target = nullptr;
  i32 (TRT_GUEST_ABI* qi)(void*, const void*, void**) = nullptr;
  if (strcmp(cls, "Windows.System.DispatcherQueueController") == 0) {
    target = &g_dqc_statics_obj;
    qi = &wrt_dqcs_QI;
  } else if (strcmp(cls, "Windows.System.DispatcherQueue") == 0) {
    target = &g_dq_statics_obj;
    qi = &wrt_dqs_QI;
  } else if (strcmp(cls, "Windows.Gaming.Input.Gamepad") == 0) {
    target = &g_gp_statics1;
    qi = &wrt_gps_QI;
  } else if (strcmp(cls, "Windows.Gaming.Input.RawGameController") == 0) {
    target = &g_rawgc_statics;
    qi = &wrt_rgcs_QI;
  } else if (strcmp(cls, "Windows.Graphics.Display.DisplayInformation") == 0) {
    target = &g_disp_statics;
    qi = &wrt_disps_QI;
  } else if (strcmp(cls, "Windows.Globalization.Language") == 0) {
    target = &g_lang_fac;
    qi = &wrt_langf_QI;
  } else if (strcmp(cls, "Windows.Globalization.ApplicationLanguages") == 0) {
    target = &g_applangs_statics;
    qi = &wrt_al_QI;
  } else if (strcmp(cls, "Windows.System.Threading.ThreadPool") == 0) {
    target = &g_wtp_statics;
    qi = &wtp_QI;
  } else if (strcmp(cls, "Windows.Storage.ApplicationData") == 0) {
    target = &g_appdata_statics;
    qi = &wrt_ads_QI;
  }
  if (!target) return REGDB_E_CLASSNOTREG_;
  if (!iid) {
    *factory = target;
    return S_OK_;
  }
  return qi(target, iid, factory);
}

}  // namespace

int trt_bridge_register_winrt(void) {
  static const trt_named_fn k_combase[] = {
#if defined(_WIN32)
      {"RoInitialize", (void*)&wrt_win32_RoInitialize},
      {"RoUninitialize", (void*)&wrt_win32_RoUninitialize},
      {"RoActivateInstance", (void*)&wrt_win32_RoActivateInstance},
      {"RoGetActivationFactory", (void*)&wrt_win32_RoGetActivationFactory},
#else
      {"RoInitialize", (void*)&wrt_RoInitialize},
      {"RoUninitialize", (void*)&wrt_RoUninitialize},
      {"RoActivateInstance", (void*)&wrt_RoActivateInstance},
      {"RoGetActivationFactory", (void*)&wrt_RoGetActivationFactory},
#endif
      {"RoGetAgileReference", (void*)&ole_RoGetAgileReference},
      {"RoSetErrorReportingFlags", (void*)&wrt_RoSetErrorReportingFlags},
      {"GetRestrictedErrorInfo", (void*)&wrt_GetRestrictedErrorInfo},
      {"SetRestrictedErrorInfo", (void*)&wrt_SetRestrictedErrorInfo},
      {"RoOriginateError", (void*)&wrt_RoOriginateError},
      {"RoOriginateErrorW", (void*)&wrt_RoOriginateErrorW},
      {"RoTransformError", (void*)&wrt_RoTransformError},
      {"RoGetBufferMarshaler", (void*)&wrt_RoGetBufferMarshaler},
#if defined(_WIN32)
      {"WindowsCreateString", (void*)&wrt_win32_WindowsCreateString},
      {"WindowsCreateStringReference",
       (void*)&wrt_win32_WindowsCreateStringReference},
      {"WindowsDeleteString", (void*)&wrt_win32_WindowsDeleteString},
      {"WindowsDuplicateString", (void*)&wrt_win32_WindowsDuplicateString},
      {"WindowsGetStringRawBuffer",
       (void*)&wrt_win32_WindowsGetStringRawBuffer},
      {"WindowsGetStringLen", (void*)&wrt_win32_WindowsGetStringLen},
      {"WindowsIsStringEmpty", (void*)&wrt_win32_WindowsIsStringEmpty},
      {"WindowsCompareStringOrdinal",
       (void*)&wrt_win32_WindowsCompareStringOrdinal},
      {"WindowsConcatString", (void*)&wrt_win32_WindowsConcatString},
#else
      {"WindowsCreateString", (void*)&wrt_WindowsCreateString},
      {"WindowsCreateStringReference",
       (void*)&wrt_WindowsCreateStringReference},
      {"WindowsDeleteString", (void*)&wrt_WindowsDeleteString},
      {"WindowsDuplicateString", (void*)&wrt_WindowsDuplicateString},
      {"WindowsGetStringRawBuffer", (void*)&wrt_WindowsGetStringRawBuffer},
      {"WindowsGetStringLen", (void*)&wrt_WindowsGetStringLen},
      {"WindowsIsStringEmpty", (void*)&wrt_WindowsIsStringEmpty},
      {"WindowsCompareStringOrdinal", (void*)&wrt_WindowsCompareStringOrdinal},
      {"WindowsConcatString", (void*)&wrt_WindowsConcatString},
#endif
      {"CoInitializeEx", (void*)&ole_CoInitializeEx},
      {"CoUninitialize", (void*)&ole_CoUninitialize},
      {"CoCreateInstance", (void*)&ole_CoCreateInstance},
      {"CoGetClassObject", (void*)&ole_CoGetClassObject},
      {"CoGetApartmentType", (void*)&ole_CoGetApartmentType},
      {"CoTaskMemAlloc", (void*)&ole_CoTaskMemAlloc},
      {"CoTaskMemRealloc", (void*)&ole_CoTaskMemRealloc},
      {"CoTaskMemFree", (void*)&ole_CoTaskMemFree},
      {"CoCreateFreeThreadedMarshaler",
       (void*)&ole_CoCreateFreeThreadedMarshaler},
      {"PropVariantClear", (void*)&ole_PropVariantClear},
      {"CoCreateGuid", (void*)&ole_CoCreateGuid},
      {"StringFromGUID2", (void*)&ole_StringFromGUID2},
      {"CoFreeUnusedLibraries", (void*)&ole_CoFreeUnusedLibraries},
  };
  constexpr int n_combase = (int)(sizeof(k_combase) / sizeof(k_combase[0]));
  trt_module_register("combase.dll", TRT_ROUTE_BUILTIN, k_combase, n_combase);
  trt_module_register("api-ms-win-core-winrt-l1-1-0.dll", TRT_ROUTE_BUILTIN,
                      k_combase, n_combase);
  trt_module_register("api-ms-win-core-winrt-string-l1-1-0.dll",
                      TRT_ROUTE_BUILTIN, k_combase, n_combase);
  trt_module_register("api-ms-win-core-winrt-error-l1-1-0.dll",
                      TRT_ROUTE_BUILTIN, k_combase, n_combase);
  trt_module_register("api-ms-win-core-winrt-error-l1-1-1.dll",
                      TRT_ROUTE_BUILTIN, k_combase, n_combase);
  trt_module_register("api-ms-win-core-winrt-robuffer-l1-1-0.dll",
                      TRT_ROUTE_BUILTIN, k_combase, n_combase);

  static const trt_named_fn k_dwrite[] = {
      {"DWriteCreateFactory", (void*)&dw_DWriteCreateFactory},
  };
  trt_module_register("dwrite.dll", TRT_ROUTE_BUILTIN, k_dwrite,
                      (int)(sizeof(k_dwrite) / sizeof(k_dwrite[0])));

  static const trt_named_fn k_uia[] = {
      {"UiaReturnRawElementProvider", (void*)&uia_UiaReturnRawElementProvider},
      {"UiaHostProviderFromHwnd", (void*)&uia_UiaHostProviderFromHwnd},
      {"UiaRaiseAutomationPropertyChangedEvent",
       (void*)&uia_UiaRaiseAutomationPropertyChangedEvent},
      {"UiaRaiseAutomationEvent", (void*)&uia_UiaRaiseAutomationEvent},
      {"UiaRaiseStructureChangedEvent",
       (void*)&uia_UiaRaiseStructureChangedEvent},
      {"UiaRaiseNotificationEvent", (void*)&uia_UiaRaiseNotificationEvent},
      {"UiaClientsAreListening", (void*)&uia_UiaClientsAreListening},
      {"UiaDisconnectAllProviders", (void*)&uia_UiaDisconnectAllProviders},
      {"UiaDisconnectProvider", (void*)&uia_UiaDisconnectProvider},
      {"UiaGetReservedNotSupportedValue",
       (void*)&uia_UiaGetReservedNotSupportedValue},
      {"UiaLookupId", (void*)&uia_UiaLookupId},
  };
  trt_module_register("uiautomationcore.dll", TRT_ROUTE_BUILTIN, k_uia,
                      (int)(sizeof(k_uia) / sizeof(k_uia[0])));

  static const trt_named_fn k_shcore[] = {
      {"GetDpiForMonitor", (void*)&shc_GetDpiForMonitor},
      {"SetProcessDpiAwareness", (void*)&shc_SetProcessDpiAwareness},
      {"GetProcessDpiAwareness", (void*)&shc_GetProcessDpiAwareness},
      {"GetScaleFactorForMonitor", (void*)&shc_GetScaleFactorForMonitor},
  };
  trt_module_register("shcore.dll", TRT_ROUTE_BUILTIN, k_shcore,
                      (int)(sizeof(k_shcore) / sizeof(k_shcore[0])));

  static const trt_named_fn k_version[] = {
      {"GetFileVersionInfoSizeW", (void*)&ver_GetFileVersionInfoSizeW},
      {"GetFileVersionInfoSizeA", (void*)&ver_GetFileVersionInfoSizeA},
      {"GetFileVersionInfoSizeExW", (void*)&ver_GetFileVersionInfoSizeExW},
      {"GetFileVersionInfoW", (void*)&ver_GetFileVersionInfoW},
      {"GetFileVersionInfoA", (void*)&ver_GetFileVersionInfoA},
      {"GetFileVersionInfoExW", (void*)&ver_GetFileVersionInfoExW},
      {"VerQueryValueW", (void*)&ver_VerQueryValueW},
      {"VerQueryValueA", (void*)&ver_VerQueryValueA},
  };
  trt_module_register("version.dll", TRT_ROUTE_BUILTIN, k_version,
                      (int)(sizeof(k_version) / sizeof(k_version[0])));
  trt_module_register("api-ms-win-core-version-l1-1-0.dll", TRT_ROUTE_BUILTIN,
                      k_version,
                      (int)(sizeof(k_version) / sizeof(k_version[0])));
  trt_module_register("api-ms-win-core-version-l1-1-1.dll", TRT_ROUTE_BUILTIN,
                      k_version,
                      (int)(sizeof(k_version) / sizeof(k_version[0])));

  static const trt_named_fn k_winhttp[] = {
      {"WinHttpOpen", (void*)&whttp_WinHttpOpen},
      {"WinHttpCloseHandle", (void*)&whttp_WinHttpCloseHandle},
      {"WinHttpGetIEProxyConfigForCurrentUser",
       (void*)&whttp_WinHttpGetIEProxyConfigForCurrentUser},
      {"WinHttpGetProxyForUrl", (void*)&whttp_WinHttpGetProxyForUrl},
      {"WinHttpConnect", (void*)&whttp_WinHttpConnect},
      {"WinHttpOpenRequest", (void*)&whttp_WinHttpOpenRequest},
      {"WinHttpSendRequest", (void*)&whttp_WinHttpSendRequest},
      {"WinHttpReceiveResponse", (void*)&whttp_WinHttpReceiveResponse},
      {"WinHttpQueryDataAvailable", (void*)&whttp_WinHttpQueryDataAvailable},
      {"WinHttpReadData", (void*)&whttp_WinHttpReadData},
      {"WinHttpQueryHeaders", (void*)&whttp_WinHttpQueryHeaders},
      {"WinHttpSetOption", (void*)&whttp_WinHttpSetOption},
      {"WinHttpQueryOption", (void*)&whttp_WinHttpQueryOption},
      {"WinHttpSetTimeouts", (void*)&whttp_WinHttpSetTimeouts},
      {"WinHttpCrackUrl", (void*)&whttp_WinHttpCrackUrl},
      {"WinHttpSetStatusCallback",
       (void*)+[](void* hInternet, void* cb, u32 notify_flags,
                  u64 reserved) TRT_GUEST_ABI -> void* {
         (void)cb; (void)notify_flags; (void)reserved;
         if (!hInternet) return (void*)(uintptr_t)-1;  // WINHTTP_INVALID_STATUS_CALLBACK
         return nullptr;
       }},
  };
  trt_module_register("winhttp.dll", TRT_ROUTE_BUILTIN, k_winhttp,
                      (int)(sizeof(k_winhttp) / sizeof(k_winhttp[0])));
  return 0;
}

}  // extern "C"
