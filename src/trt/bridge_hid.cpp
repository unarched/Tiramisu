// tiramisu/src/trt/bridge_hid.cpp
// HID (hid.dll) + SetupAPI (setupapi.dll) bridge. See bridge_hid.h.
#include "bridge_hid.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>
#include <string.h>

namespace hidlog {
static void line(const char* s) { trt_core_log(s); }
}  // namespace hidlog

extern "C" void TRT_GUEST_ABI trt_SetLastError(u32 e);

namespace {

constexpr u32 k_err_invalid_handle = 6u;
constexpr u32 k_err_invalid_parameter = 87u;
constexpr u32 k_err_no_more_items = 259u;
constexpr u32 k_err_not_found = 1168u;
constexpr u32 k_hidp_status_invalid_preparsed_data = 0xC0110001u;

// Standard Windows GUID_DEVINTERFACE_HID: {4D1E55B2-F16F-11CF-88CB-001111000030}
struct raw_guid {
  u32 d1;
  u16 d2;
  u16 d3;
  u8 d4[8];
};
constexpr raw_guid k_hid_guid = {
    0x4D1E55B2u,
    0xF16Fu,
    0x11CFu,
    {0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};

// SetupAPI HDEVINFO record table (ported from xboxnative uwph/hid/backend.c)
constexpr int k_max_devinfo = 32;
constexpr u32 k_devinfo_tag = 0x53440000u;  // 'SD'

struct devinfo_set {
  bool used;
  raw_guid class_guid;
  u32 flags;
};

devinfo_set g_devsets[k_max_devinfo];

void* alloc_devset(const void* guid, u32 flags) {
  for (int i = 0; i < k_max_devinfo; ++i) {
    if (!g_devsets[i].used) {
      g_devsets[i].used = true;
      if (guid)
        memcpy(&g_devsets[i].class_guid, guid, sizeof(raw_guid));
      else
        memset(&g_devsets[i].class_guid, 0, sizeof(raw_guid));
      g_devsets[i].flags = flags;
      return (void*)(uintptr_t)(k_devinfo_tag | (u32)(i + 1));
    }
  }
  return (void*)(uintptr_t)-1;  // INVALID_HANDLE_VALUE
}

devinfo_set* find_devset(void* h) {
  if (!h || h == (void*)(uintptr_t)-1) return nullptr;
  const u32 v = (u32)(uintptr_t)h;
  if ((v & 0xFFFF0000u) != k_devinfo_tag) return nullptr;
  const u32 idx = (v & 0xFFFFu);
  if (idx == 0 || idx > (u32)k_max_devinfo) return nullptr;
  return g_devsets[idx - 1].used ? &g_devsets[idx - 1] : nullptr;
}

}  // namespace

extern "C" {

// ===========================================================================
// hid.dll
// ===========================================================================

void TRT_GUEST_ABI trt_HidD_GetHidGuid(void* guid_out) {
  if (guid_out) memcpy(guid_out, &k_hid_guid, sizeof(k_hid_guid));
}

int TRT_GUEST_ABI trt_HidD_GetAttributes(void* dev, void* attrib) {
  (void)dev;
  (void)attrib;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetPreparsedData(void* dev, void** out) {
  (void)dev;
  if (out) *out = nullptr;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_FreePreparsedData(void* data) {
  (void)data;
  return 1;
}

int TRT_GUEST_ABI trt_HidD_GetManufacturerString(void* dev, void* buf,
                                                 u32 bytes) {
  (void)dev;
  if (buf && bytes >= 2) *(u16*)buf = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetProductString(void* dev, void* buf, u32 bytes) {
  (void)dev;
  if (buf && bytes >= 2) *(u16*)buf = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetSerialNumberString(void* dev, void* buf,
                                                 u32 bytes) {
  (void)dev;
  if (buf && bytes >= 2) *(u16*)buf = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetPhysicalDescriptor(void* dev, void* buf,
                                                 u32 bytes) {
  (void)dev;
  (void)buf;
  (void)bytes;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetIndexedString(void* dev, u32 idx, void* buf,
                                            u32 bytes) {
  (void)dev;
  (void)idx;
  if (buf && bytes >= 2) *(u16*)buf = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetFeature(void* dev, void* buf, u32 bytes) {
  (void)dev;
  (void)buf;
  (void)bytes;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_SetFeature(void* dev, const void* buf, u32 bytes) {
  (void)dev;
  (void)buf;
  (void)bytes;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_GetInputReport(void* dev, void* buf, u32 bytes) {
  (void)dev;
  (void)buf;
  (void)bytes;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_SetOutputReport(void* dev, const void* buf,
                                           u32 bytes) {
  (void)dev;
  (void)buf;
  (void)bytes;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_HidD_FlushQueue(void* dev) {
  (void)dev;
  return 1;
}

int TRT_GUEST_ABI trt_HidD_SetNumInputBuffers(void* dev, u32 num) {
  (void)dev;
  (void)num;
  return 1;
}

u32 TRT_GUEST_ABI trt_HidP_GetCaps(void* preparsed, void* caps) {
  (void)preparsed;
  if (caps) memset(caps, 0, 64);
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_GetButtonCaps(int type, void* caps, u16* len,
                                         void* preparsed) {
  (void)type;
  (void)caps;
  (void)preparsed;
  if (len) *len = 0;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_GetValueCaps(int type, void* caps, u16* len,
                                        void* preparsed) {
  (void)type;
  (void)caps;
  (void)preparsed;
  if (len) *len = 0;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_GetUsages(int type, u16 page, u16 link, u16* list,
                                     u32* len, void* preparsed,
                                     const char* report, u32 rlen) {
  (void)type;
  (void)page;
  (void)link;
  (void)list;
  (void)preparsed;
  (void)report;
  (void)rlen;
  if (len) *len = 0;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_GetUsageValue(int type, u16 page, u16 link,
                                         u16 usage, u32* val, void* preparsed,
                                         const char* report, u32 rlen) {
  (void)type;
  (void)page;
  (void)link;
  (void)usage;
  (void)preparsed;
  (void)report;
  (void)rlen;
  if (val) *val = 0;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_GetScaledUsageValue(int type, u16 page, u16 link,
                                               u16 usage, i32* val,
                                               void* preparsed,
                                               const char* report, u32 rlen) {
  (void)type;
  (void)page;
  (void)link;
  (void)usage;
  (void)preparsed;
  (void)report;
  (void)rlen;
  if (val) *val = 0;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_MaxUsageListLength(int type, u16 page,
                                              void* preparsed) {
  (void)type;
  (void)page;
  (void)preparsed;
  return 0;
}

u32 TRT_GUEST_ABI trt_HidP_GetData(int type, void* data_list, u32* data_len,
                                   void* preparsed, const char* report,
                                   u32 rlen) {
  (void)type;
  (void)data_list;
  (void)preparsed;
  (void)report;
  (void)rlen;
  if (data_len) *data_len = 0;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_MaxDataListLength(int type, void* preparsed) {
  (void)type;
  (void)preparsed;
  return 0;
}

u32 TRT_GUEST_ABI trt_HidP_SetUsages(int type, u16 page, u16 link, u16* list,
                                     u32* len, void* preparsed, char* report,
                                     u32 rlen) {
  (void)type; (void)page; (void)link; (void)list; (void)len;
  (void)preparsed; (void)report; (void)rlen;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_SetUsageValue(int type, u16 page, u16 link,
                                         u16 usage, u32 val, void* preparsed,
                                         char* report, u32 rlen) {
  (void)type; (void)page; (void)link; (void)usage; (void)val;
  (void)preparsed; (void)report; (void)rlen;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_SetUsageValueArray(int type, u16 page, u16 link,
                                              u16 usage, void* usage_value,
                                              u16 byte_len, void* preparsed,
                                              char* report, u32 rlen) {
  (void)type; (void)page; (void)link; (void)usage; (void)usage_value;
  (void)byte_len; (void)preparsed; (void)report; (void)rlen;
  return k_hidp_status_invalid_preparsed_data;
}

u32 TRT_GUEST_ABI trt_HidP_InitializeReportForID(int type, u8 report_id,
                                                 void* preparsed, char* report,
                                                 u32 rlen) {
  (void)type; (void)report_id; (void)preparsed;
  if (report && rlen > 0) memset(report, 0, rlen);
  return k_hidp_status_invalid_preparsed_data;
}

// ===========================================================================
// setupapi.dll
// ===========================================================================

void* TRT_GUEST_ABI trt_SetupDiCreateDeviceInfoList(const void* cls_guid,
                                                    void* hwnd_parent) {
  (void)hwnd_parent;
  void* h = alloc_devset(cls_guid, 0);
  if (h == (void*)(uintptr_t)-1) trt_SetLastError(k_err_invalid_parameter);
  return h;
}

void* TRT_GUEST_ABI trt_SetupDiGetClassDevsW(const void* cls_guid,
                                             const u16* enumerator,
                                             void* hwnd_parent, u32 flags) {
  (void)enumerator;
  (void)hwnd_parent;
  void* h = alloc_devset(cls_guid, flags);
  if (h == (void*)(uintptr_t)-1) {
    trt_SetLastError(k_err_invalid_parameter);
    return h;
  }
  hidlog::line(
      "setupapi: SetupDiGetClassDevsW -> empty HDEVINFO (0 raw HID nodes; "
      "gamepads route through XInput)");
  return h;
}

void* TRT_GUEST_ABI trt_SetupDiGetClassDevsA(const void* cls_guid,
                                             const char* enumerator,
                                             void* hwnd_parent, u32 flags) {
  (void)enumerator;
  return trt_SetupDiGetClassDevsW(cls_guid, nullptr, hwnd_parent, flags);
}

int TRT_GUEST_ABI trt_SetupDiDestroyDeviceInfoList(void* dev_info) {
  devinfo_set* s = find_devset(dev_info);
  if (!s) {
    trt_SetLastError(k_err_invalid_handle);
    return 0;
  }
  s->used = false;
  return 1;
}

int TRT_GUEST_ABI trt_SetupDiEnumDeviceInfo(void* dev_info, u32 index,
                                            void* data_out) {
  (void)index;
  (void)data_out;
  if (!find_devset(dev_info)) {
    trt_SetLastError(k_err_invalid_handle);
    return 0;
  }
  trt_SetLastError(k_err_no_more_items);
  return 0;
}

int TRT_GUEST_ABI trt_SetupDiEnumDeviceInterfaces(void* dev_info,
                                                  void* dev_data,
                                                  const void* iface_guid,
                                                  u32 index,
                                                  void* iface_data_out) {
  (void)dev_data;
  (void)iface_guid;
  (void)index;
  (void)iface_data_out;
  if (!find_devset(dev_info)) {
    trt_SetLastError(k_err_invalid_handle);
    return 0;
  }
  trt_SetLastError(k_err_no_more_items);
  return 0;
}

int TRT_GUEST_ABI trt_SetupDiGetDeviceInterfaceDetailW(
    void* dev_info, void* iface_data, void* detail, u32 detail_size,
    u32* required, void* dev_data) {
  (void)iface_data;
  (void)detail;
  (void)detail_size;
  (void)dev_data;
  if (required) *required = 0;
  if (!find_devset(dev_info)) {
    trt_SetLastError(k_err_invalid_handle);
    return 0;
  }
  trt_SetLastError(k_err_no_more_items);
  return 0;
}

int TRT_GUEST_ABI trt_SetupDiGetDeviceInterfaceDetailA(
    void* dev_info, void* iface_data, void* detail, u32 detail_size,
    u32* required, void* dev_data) {
  return trt_SetupDiGetDeviceInterfaceDetailW(dev_info, iface_data, detail,
                                              detail_size, required, dev_data);
}

int TRT_GUEST_ABI trt_SetupDiGetDeviceRegistryPropertyW(
    void* dev_info, void* dev_data, u32 prop, u32* reg_type, u8* buf, u32 size,
    u32* required) {
  (void)dev_info;
  (void)dev_data;
  (void)prop;
  (void)buf;
  (void)size;
  if (reg_type) *reg_type = 0;
  if (required) *required = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_SetupDiGetDeviceRegistryPropertyA(
    void* dev_info, void* dev_data, u32 prop, u32* reg_type, u8* buf, u32 size,
    u32* required) {
  return trt_SetupDiGetDeviceRegistryPropertyW(dev_info, dev_data, prop,
                                               reg_type, buf, size, required);
}

int TRT_GUEST_ABI trt_SetupDiGetDeviceInstanceIdW(void* dev_info,
                                                  void* dev_data, u16* id_out,
                                                  u32 size, u32* required) {
  (void)dev_info;
  (void)dev_data;
  if (id_out && size > 0) id_out[0] = 0;
  if (required) *required = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

int TRT_GUEST_ABI trt_SetupDiGetDeviceInstanceIdA(void* dev_info,
                                                  void* dev_data, char* id_out,
                                                  u32 size, u32* required) {
  (void)dev_info;
  (void)dev_data;
  if (id_out && size > 0) id_out[0] = 0;
  if (required) *required = 0;
  trt_SetLastError(k_err_not_found);
  return 0;
}

void* TRT_GUEST_ABI trt_SetupDiOpenDevRegKey(void* dev_info, void* dev_data,
                                             u32 scope, u32 hw_profile,
                                             u32 key_type, u32 sam) {
  (void)dev_info;
  (void)dev_data;
  (void)scope;
  (void)hw_profile;
  (void)key_type;
  (void)sam;
  trt_SetLastError(k_err_not_found);
  return (void*)(uintptr_t)-1;
}

// ---- CFGMGR32-style device-node queries (imported by SDL3 via SETUPAPI) ----
// SDL3 walks SetupDiGetClassDevsA -> EnumDeviceInfo -> DeviceInstanceId ->
// CM_Locate_DevNodeA -> CM_Get_Parent -> CM_Get_Device_IDA to build a stable
// gamepad ID. The console exposes no Plug&Play tree, so: locating a node
// synthesizes a stable devinst from the ID string, the parent query reports
// CR_NO_SUCH_DEVNODE (SDL then uses the instance ID as-is — the honest
// answer: this device has no enumerable parent), and the ID query returns the
// synthetic ID it was located under.
static u32 hid_devinst_from_id(const char* id) {
  u32 h = 2166136261u;
  for (const char* p = id; p && *p; ++p) {
    h ^= (u8)*p;
    h *= 16777619u;
  }
  return h ? h : 1u;  // devinst 0 is reserved-ish; never hand back 0
}

i32 TRT_GUEST_ABI hid_CM_Locate_DevNodeA(u32* devinst, const char* device_id,
                                          u32 flags) {
  if (!devinst || !device_id || !device_id[0]) {
    hidlog::line("setupapi: CM_Locate_DevNodeA -> CR_INVALID_DEVINST");
    return 0x0D;  // CR_INVALID_DEVINST
  }
  *devinst = hid_devinst_from_id(device_id);
  char _l[160];
  snprintf(_l, sizeof(_l),
           "setupapi: CM_Locate_DevNodeA(%s) -> synthetic devinst 0x%08x",
           device_id, *devinst);
  hidlog::line(_l);
  return 0;  // CR_SUCCESS
}

i32 TRT_GUEST_ABI hid_CM_Get_Parent(u32* parent_devinst, u32 devinst,
                                     u32 flags) {
  (void)devinst;
  (void)flags;
  if (parent_devinst) *parent_devinst = 0;
  char _l[160];
  snprintf(_l, sizeof(_l),
           "setupapi: CM_Get_Parent(0x%08x) -> CR_NO_SUCH_DEVNODE (no PnP "
           "tree on console; caller falls back to the instance ID)",
           devinst);
  hidlog::line(_l);
  return 0x0E;  // CR_NO_SUCH_DEVNODE
}

i32 TRT_GUEST_ABI hid_CM_Get_Device_IDA(u32 devinst, char* buf, u32 buf_len,
                                         u32 flags) {
  if (!buf || buf_len == 0) {
    hidlog::line("setupapi: CM_Get_Device_IDA -> CR_INVALID_BUFFER");
    return 0x03;  // CR_INVALID_BUFFER (closest CR code)
  }
  u32 h = devinst ? devinst : 1u;
  char id[64];
  snprintf(id, sizeof(id), "TRT\\DEVINST_%08x", h);
  if (strlen(id) + 1 > buf_len) {
    char _l[96];
    snprintf(_l, sizeof(_l), "setupapi: CM_Get_Device_IDA -> CR_BUFFER_SMALL");
    hidlog::line(_l);
    return 0x03;
  }
  memcpy(buf, id, strlen(id) + 1);
  char _l[128];
  snprintf(_l, sizeof(_l), "setupapi: CM_Get_Device_IDA(0x%08x) -> \"%s\"",
           devinst, id);
  hidlog::line(_l);
  return 0;  // CR_SUCCESS
}

int trt_bridge_register_hid(void) {
  static const trt_named_fn k_hid_fns[] = {
      {"HidD_GetHidGuid", (void*)&trt_HidD_GetHidGuid},
      {"HidD_GetAttributes", (void*)&trt_HidD_GetAttributes},
      {"HidD_GetPreparsedData", (void*)&trt_HidD_GetPreparsedData},
      {"HidD_FreePreparsedData", (void*)&trt_HidD_FreePreparsedData},
      {"HidD_GetManufacturerString", (void*)&trt_HidD_GetManufacturerString},
      {"HidD_GetProductString", (void*)&trt_HidD_GetProductString},
      {"HidD_GetSerialNumberString", (void*)&trt_HidD_GetSerialNumberString},
      {"HidD_GetPhysicalDescriptor", (void*)&trt_HidD_GetPhysicalDescriptor},
      {"HidD_GetIndexedString", (void*)&trt_HidD_GetIndexedString},
      {"HidD_GetFeature", (void*)&trt_HidD_GetFeature},
      {"HidD_SetFeature", (void*)&trt_HidD_SetFeature},
      {"HidD_GetInputReport", (void*)&trt_HidD_GetInputReport},
      {"HidD_SetOutputReport", (void*)&trt_HidD_SetOutputReport},
      {"HidD_FlushQueue", (void*)&trt_HidD_FlushQueue},
      {"HidD_SetNumInputBuffers", (void*)&trt_HidD_SetNumInputBuffers},
      {"HidP_GetCaps", (void*)&trt_HidP_GetCaps},
      {"HidP_GetButtonCaps", (void*)&trt_HidP_GetButtonCaps},
      {"HidP_GetValueCaps", (void*)&trt_HidP_GetValueCaps},
      {"HidP_GetUsages", (void*)&trt_HidP_GetUsages},
      {"HidP_GetUsageValue", (void*)&trt_HidP_GetUsageValue},
      {"HidP_GetScaledUsageValue", (void*)&trt_HidP_GetScaledUsageValue},
      {"HidP_MaxUsageListLength", (void*)&trt_HidP_MaxUsageListLength},
      {"HidP_GetData", (void*)&trt_HidP_GetData},
      {"HidP_MaxDataListLength", (void*)&trt_HidP_MaxDataListLength},
      {"HidP_SetUsages", (void*)&trt_HidP_SetUsages},
      {"HidP_SetUsageValue", (void*)&trt_HidP_SetUsageValue},
      {"HidP_SetUsageValueArray", (void*)&trt_HidP_SetUsageValueArray},
      {"HidP_InitializeReportForID", (void*)&trt_HidP_InitializeReportForID},
  };
  static const trt_named_fn k_setupapi_fns[] = {
      {"SetupDiCreateDeviceInfoList", (void*)&trt_SetupDiCreateDeviceInfoList},
      {"SetupDiGetClassDevsW", (void*)&trt_SetupDiGetClassDevsW},
      {"SetupDiGetClassDevsA", (void*)&trt_SetupDiGetClassDevsA},
      {"SetupDiDestroyDeviceInfoList",
       (void*)&trt_SetupDiDestroyDeviceInfoList},
      {"SetupDiEnumDeviceInfo", (void*)&trt_SetupDiEnumDeviceInfo},
      {"SetupDiEnumDeviceInterfaces", (void*)&trt_SetupDiEnumDeviceInterfaces},
      {"SetupDiGetDeviceInterfaceDetailW",
       (void*)&trt_SetupDiGetDeviceInterfaceDetailW},
      {"SetupDiGetDeviceInterfaceDetailA",
       (void*)&trt_SetupDiGetDeviceInterfaceDetailA},
      {"SetupDiGetDeviceRegistryPropertyW",
       (void*)&trt_SetupDiGetDeviceRegistryPropertyW},
      {"SetupDiGetDeviceRegistryPropertyA",
       (void*)&trt_SetupDiGetDeviceRegistryPropertyA},
      {"SetupDiGetDeviceInstanceIdW", (void*)&trt_SetupDiGetDeviceInstanceIdW},
      {"SetupDiGetDeviceInstanceIdA", (void*)&trt_SetupDiGetDeviceInstanceIdA},
      {"SetupDiOpenDevRegKey", (void*)&trt_SetupDiOpenDevRegKey},
      {"CM_Locate_DevNodeA", (void*)&hid_CM_Locate_DevNodeA},
      {"CM_Get_Parent", (void*)&hid_CM_Get_Parent},
      {"CM_Get_Device_IDA", (void*)&hid_CM_Get_Device_IDA},
  };
  trt_module_register("hid.dll", TRT_ROUTE_BUILTIN, k_hid_fns,
                      (int)(sizeof(k_hid_fns) / sizeof(k_hid_fns[0])));
  trt_module_register(
      "setupapi.dll", TRT_ROUTE_BUILTIN, k_setupapi_fns,
      (int)(sizeof(k_setupapi_fns) / sizeof(k_setupapi_fns[0])));
  return 0;
}

}  // extern "C"
