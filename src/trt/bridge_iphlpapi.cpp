// tiramisu/src/trt/bridge_iphlpapi.cpp
// iphlpapi bridge. See bridge_iphlpapi.h.
//
// Adapter/interface tables are NOT trivially available in-process on the
// console, so the honest answer is no-data (ERROR_NO_DATA / zero adapters)
// with a named log. The ICMP probe trio UnityPlayer imports gets real
// handle records; SendEcho honestly fails (no raw sockets for the guest).
#include "bridge_iphlpapi.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

namespace {
constexpr u32 k_err_no_data = 232;      // ERROR_NO_DATA
constexpr u32 k_err_invalid_parameter = 87;
constexpr u32 k_err_invalid_handle = 6;

// ICMP handle records (tag 0x49 = 'I')
struct icmp_rec { u32 tag; };
icmp_rec g_icmp[8];

void* icmp_alloc(void) {
  for (u32 i = 0; i < 8; ++i) {
    if (!g_icmp[i].tag) {
      g_icmp[i].tag = 0x49u;
      return (void*)(uintptr_t)(0x49000000u | i);
    }
  }
  return nullptr;
}
bool icmp_valid(void* h) {
  const u32 v = (u32)(uintptr_t)h;
  return (v >> 24) == 0x49u && (v & 0xFFFFFFu) < 8 && g_icmp[v & 0xFFFFFFu].tag;
}
void icmp_free(void* h) {
  const u32 v = (u32)(uintptr_t)h;
  if ((v >> 24) == 0x49u && (v & 0xFFFFFFu) < 8) g_icmp[v & 0xFFFFFFu].tag = 0;
}

namespace iphlplog {
static void line(const char* s) { trt_core_log(s); }
}
#define log_line(s_) iphlplog::line(s_)

}  // namespace

extern "C" {

u32 TRT_GUEST_ABI iphlp_GetAdaptersInfo(void* info, u32* len) {
  char line[128];
  // real semantics: NULL buf or too-small cb returns the required size;
  // with no adapters the honest answer is NO_DATA
  if (!len) {
    snprintf(line, sizeof(line),
             "iphlpapi: GetAdaptersInfo -> ERROR_INVALID_PARAMETER (null len)");
    log_line(line);
    return k_err_invalid_parameter;
  }
  *len = 0;
  snprintf(line, sizeof(line),
           "iphlpapi: GetAdaptersInfo -> ERROR_NO_DATA (0 adapters: no "
           "network stack for the guest on console)");
  log_line(line);
  return k_err_no_data;
}

u32 TRT_GUEST_ABI iphlp_GetAdaptersAddresses(u32 family, u32 flags, void* rsv,
                                             void* aa, u32* len) {
  (void)family; (void)flags; (void)rsv;
  char line[160];
  if (!len) {
    snprintf(line, sizeof(line),
             "iphlpapi: GetAdaptersAddresses -> ERROR_INVALID_PARAMETER (null "
             "len)");
    log_line(line);
    return k_err_invalid_parameter;
  }
  *len = 0;
  if (aa) *(u32*)aa = 0;  // zero adapter records — honest empty
  snprintf(line, sizeof(line),
           "iphlpapi: GetAdaptersAddresses -> ERROR_NO_DATA (0 adapters: no "
           "network stack for the guest on console)");
  log_line(line);
  return k_err_no_data;
}

u32 TRT_GUEST_ABI iphlp_GetIfTable(void* table, u32* size, int ordered) {
  (void)ordered;
  char line[128];
  if (!size) {
    snprintf(line, sizeof(line),
             "iphlpapi: GetIfTable -> ERROR_INVALID_PARAMETER (null size)");
    log_line(line);
    return k_err_invalid_parameter;
  }
  if (!table) {
    if (size) *size = 4;  // room for a zero row count
    return k_err_no_data;
  }
  *(u32*)table = 0;  // zero interface rows — honest empty
  snprintf(line, sizeof(line),
           "iphlpapi: GetIfTable -> 0 rows (honest empty: no interfaces)");
  log_line(line);
  return 0;  // NO_ERROR with an empty table is the real Windows shape
}

// ---- ICMP probe surface (UnityPlayer imports it) ----
void* TRT_GUEST_ABI iphlp_IcmpCreateFile(void) {
  char line[128];
  void* h = icmp_alloc();
  snprintf(line, sizeof(line),
           "iphlpapi: IcmpCreateFile -> %s (handle record; echo honestly "
           "fails)", h ? "handle" : "NULL");
  log_line(line);
  return h;
}

int TRT_GUEST_ABI iphlp_IcmpCloseHandle(void* h) {
  char line[128];
  if (!icmp_valid(h)) {
    snprintf(line, sizeof(line),
             "iphlpapi: IcmpCloseHandle -> FALSE (invalid handle)");
    log_line(line);
    return 0;
  }
  icmp_free(h);
  snprintf(line, sizeof(line), "iphlpapi: IcmpCloseHandle -> freed record");
  log_line(line);
  return 1;
}

int TRT_GUEST_ABI iphlp_IcmpSendEcho(void* h, u32 dest, void* send, u16 ssize,
                                     void* opts, void* reply, u32 rsize,
                                     u32 timeout) {
  char line[160];
  (void)ssize; (void)opts; (void)reply; (void)timeout;
  if (!icmp_valid(h)) {
    snprintf(line, sizeof(line),
             "iphlpapi: IcmpSendEcho -> 0 (invalid handle)");
    log_line(line);
    return 0;
  }
  (void)send;
  snprintf(line, sizeof(line),
           "iphlpapi: IcmpSendEcho -> 0 (ERROR_NO_DATA: no raw sockets for "
           "the guest on console; dest=0x%08x)", dest);
  log_line(line);
  return 0;
}

// GetNetworkParams: no network stack for the guest -> honest NO_DATA.
u32 TRT_GUEST_ABI iphlp_GetNetworkParams(void* fixed_info, u32* len) {
  char line[128];
  if (!len) {
    snprintf(line, sizeof(line),
             "iphlpapi: GetNetworkParams -> ERROR_INVALID_PARAMETER (null len)");
    log_line(line);
    return k_err_invalid_parameter;
  }
  *len = 0;
  snprintf(line, sizeof(line),
           "iphlpapi: GetNetworkParams -> ERROR_NO_DATA (no network stack "
           "for the guest on console)");
  log_line(line);
  return k_err_no_data;
}

// GetIfEntry: same honest surface as GetIfTable — a single MIB_IFROW-shaped
// read the guest may do per adapter; with no interfaces, fail with NO_DATA.
u32 TRT_GUEST_ABI iphlp_GetIfEntry(void* row) {
  char line[128];
  if (!row) {
    snprintf(line, sizeof(line),
             "iphlpapi: GetIfEntry -> ERROR_INVALID_PARAMETER (null row)");
    log_line(line);
    return k_err_invalid_parameter;
  }
  snprintf(line, sizeof(line),
           "iphlpapi: GetIfEntry -> ERROR_NO_DATA (no interfaces: no network "
           "stack for the guest on console)");
  log_line(line);
  return k_err_no_data;
}

u32 TRT_GUEST_ABI iphlp_GetBestInterfaceEx(const void* dest_addr, u32* best_if) {
  if (!dest_addr || !best_if) return k_err_invalid_parameter;
  *best_if = 0;
  return 50;  // ERROR_NOT_SUPPORTED (fail-visible: offline network bridge)
}

u32 TRT_GUEST_ABI iphlp_if_nametoindex(const char* ifname) {
  (void)ifname;
  return 0;  // 0 = interface not found
}

u32 TRT_GUEST_ABI iphlp_GetIpAddrTable(void* table, u32* size, int order) {
  (void)order;
  if (!size) return k_err_invalid_parameter;
  // MIB_IPADDRTABLE { DWORD dwNumEntries; MIB_IPADDRROW table[1]; } = 28 bytes min
  const u32 need = 28u;
  if (!table || *size < need) {
    *size = need;
    return 122u;  // ERROR_INSUFFICIENT_BUFFER
  }
  memset(table, 0, need);
  u8* p = (u8*)table;
  *(u32*)(p + 0) = 1u;              // dwNumEntries
  *(u32*)(p + 4) = 0x0100007Fu;     // dwAddr = 127.0.0.1 (network byte order)
  *(u32*)(p + 8) = 1u;              // dwIndex = 1
  *(u32*)(p + 12) = 0x000000FFu;    // dwMask = 255.0.0.0
  *(u32*)(p + 16) = 0xFF00007Fu;    // dwBCastAddr = 127.255.255.255
  *(u32*)(p + 20) = 65535u;         // dwReasmSize
  *(u16*)(p + 24) = 1u;             // wType = MIB_IPADDR_PRIMARY
  *size = need;
  return 0u;  // NO_ERROR
}

void TRT_GUEST_ABI dns_DnsFree(void* data, u32 free_type) {
  (void)data;
  (void)free_type;
}

u32 TRT_GUEST_ABI dns_DnsQuery_A(const char* name, u16 type, u32 opts, void* extra,
                                 void** results, void* reserved) {
  (void)name; (void)type; (void)opts; (void)extra; (void)reserved;
  if (results) *results = nullptr;
  return 9003u;  // DNS_ERROR_RCODE_NAME_ERROR (honest offline NXDOMAIN)
}

u32 TRT_GUEST_ABI dns_DnsQuery_W(const u16* name, u16 type, u32 opts, void* extra,
                                 void** results, void* reserved) {
  (void)name; (void)type; (void)opts; (void)extra; (void)reserved;
  if (results) *results = nullptr;
  return 9003u;
}

int trt_bridge_register_iphlpapi(void) {
  static const trt_named_fn k_fns[] = {
      {"GetAdaptersInfo", (void*)&iphlp_GetAdaptersInfo},
      {"GetAdaptersAddresses", (void*)&iphlp_GetAdaptersAddresses},
      {"GetIfTable", (void*)&iphlp_GetIfTable},
      {"GetIpAddrTable", (void*)&iphlp_GetIpAddrTable},
      {"GetNetworkParams", (void*)&iphlp_GetNetworkParams},
      {"GetIfEntry", (void*)&iphlp_GetIfEntry},
      {"IcmpCreateFile", (void*)&iphlp_IcmpCreateFile},
      {"IcmpCloseHandle", (void*)&iphlp_IcmpCloseHandle},
      {"IcmpSendEcho", (void*)&iphlp_IcmpSendEcho},
      {"GetBestInterfaceEx", (void*)&iphlp_GetBestInterfaceEx},
      {"if_nametoindex", (void*)&iphlp_if_nametoindex},
  };
  trt_module_register("iphlpapi.dll", TRT_ROUTE_BUILTIN, k_fns,
                      (int)(sizeof(k_fns) / sizeof(k_fns[0])));
  static const trt_named_fn k_dns_fns[] = {
      {"DnsFree", (void*)&dns_DnsFree},
      {"DnsRecordListFree", (void*)&dns_DnsFree},
      {"DnsQuery_A", (void*)&dns_DnsQuery_A},
      {"DnsQuery_W", (void*)&dns_DnsQuery_W},
      {"DnsQuery_UTF8", (void*)&dns_DnsQuery_A},
  };
  trt_module_register("dnsapi.dll", TRT_ROUTE_BUILTIN, k_dns_fns,
                      (int)(sizeof(k_dns_fns) / sizeof(k_dns_fns[0])));
  return 0;
}

}  // extern "C"
