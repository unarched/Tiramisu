// tiramisu/src/trt/bridge_ws2.cpp
// WinSock2 (ws2_32.dll) + WinSock 1.1 (wsock32.dll) runtime bridge.
//
// Translates Win64 socket ABIs (WSADATA, fd_set, timeval, addrinfo/ADDRINFOW,
// ADDRINFOEXW, WSABUF, WSAPOLLFD, WSANETWORKEVENTS, hostent, protoent, AF_INET6,
// SOL_SOCKET/SO_* options, FIONBIO/FIONREAD, errno -> WSAE*) onto POSIX sockets
// on Linux offline hosts, and forwards cleanly onto <winsock2.h> on Windows UWP.
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WINSOCK_DEPRECATED_NO_WARNINGS
#    define _WINSOCK_DEPRECATED_NO_WARNINGS
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#include "bridge_ws2.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#  include <arpa/inet.h>
#  include <errno.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <poll.h>
#  include <pthread.h>
#  include <sys/ioctl.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/uio.h>
#  include <unistd.h>
#endif

namespace {

void ws2_log(const char* s) { trt_core_log(s); }

#if !defined(_WIN32)

// ---------- Win64 ABI constants & structs ---------------------------------
constexpr u64 k_invalid_socket = ~(u64)0;
constexpr i32 k_socket_error = -1;

constexpr i32 k_win_af_unspec = 0;
constexpr i32 k_win_af_inet = 2;
constexpr i32 k_win_af_inet6 = 23;

constexpr i32 k_win_sol_socket = 0xffff;
constexpr i32 k_win_so_reuseaddr = 0x0004;
constexpr i32 k_win_so_keepalive = 0x0008;
constexpr i32 k_win_so_broadcast = 0x0020;
constexpr i32 k_win_so_linger = 0x0080;
constexpr i32 k_win_so_sndbuf = 0x1001;
constexpr i32 k_win_so_rcvbuf = 0x1002;
constexpr i32 k_win_so_sndtimeo = 0x1005;
constexpr i32 k_win_so_rcvtimeo = 0x1006;
constexpr i32 k_win_so_error = 0x1007;

constexpr i32 k_win_ipproto_tcp = 6;
constexpr i32 k_win_ipproto_ipv6 = 41;
constexpr i32 k_win_tcp_nodelay = 1;
constexpr i32 k_win_ipv6_v6only = 27;

constexpr u32 k_win_fionbio = 0x8004667eu;
constexpr u32 k_win_fionread = 0x4004667fu;

constexpr i32 k_wsa_einval = 10022;
constexpr i32 k_wsa_efault = 10014;
constexpr i32 k_wsa_ewouldblock = 10035;
constexpr i32 k_wsa_eopnotsupp = 10045;
constexpr i32 k_wsa_enotsock = 10038;
constexpr i32 k_wsa_host_not_found = 11001;
constexpr i32 k_wsa_eafnosupport = 10047;

constexpr i32 k_fd_read = 1 << 0;
constexpr i32 k_fd_write = 1 << 1;
constexpr i32 k_fd_accept = 1 << 3;
constexpr i32 k_fd_connect = 1 << 4;
constexpr i32 k_fd_close = 1 << 5;
constexpr int k_fd_max_events = 10;

constexpr i16 k_win_pollerr = 0x0001;
constexpr i16 k_win_pollhup = 0x0002;
constexpr i16 k_win_pollnval = 0x0004;
constexpr i16 k_win_pollwrnorm = 0x0010;
constexpr i16 k_win_pollrdnorm = 0x0100;
constexpr i16 k_win_pollrdband = 0x0200;

struct win64_wsadata {
  u16 wVersion;
  u16 wHighVersion;
  u16 iMaxSockets;
  u16 iMaxUdpDg;
  u64 lpVendorInfo;
  char szDescription[257];
  char szSystemStatus[129];
};

struct win64_fd_set {
  u32 fd_count;
  u32 _pad;
  u64 fd_array[64];
};

struct win64_timeval {
  i32 tv_sec;
  i32 tv_usec;
};

struct win64_wsabuf {
  u32 len;
  u32 _pad;
  char* buf;
};

struct win64_pollfd {
  u64 fd;
  i16 events;
  i16 revents;
  i32 _pad;
};

struct win64_network_events {
  i32 lNetworkEvents;
  i32 iErrorCode[k_fd_max_events];
};

struct win64_addrinfo_a {
  i32 ai_flags;
  i32 ai_family;
  i32 ai_socktype;
  i32 ai_protocol;
  u64 ai_addrlen;
  char* ai_canonname;
  u8* ai_addr;
  win64_addrinfo_a* ai_next;
};

struct win64_addrinfo_w {
  i32 ai_flags;
  i32 ai_family;
  i32 ai_socktype;
  i32 ai_protocol;
  u64 ai_addrlen;
  u16* ai_canonname;
  u8* ai_addr;
  win64_addrinfo_w* ai_next;
};

struct win64_addrinfo_exw {
  i32 ai_flags;
  i32 ai_family;
  i32 ai_socktype;
  i32 ai_protocol;
  u64 ai_addrlen;
  u16* ai_canonname;
  u8* ai_addr;
  void* ai_blob;
  u64 ai_bloblen;
  void* ai_provider;
  win64_addrinfo_exw* ai_next;
};

struct win64_hostent {
  char* h_name;
  char** h_aliases;
  i16 h_addrtype;
  i16 h_length;
  u32 _pad;
  char** h_addr_list;
};

struct win64_protoent {
  char* p_name;
  char** p_aliases;
  i16 p_proto;
  i16 _pad[3];
};

struct win64_overlapped {
  u64 Internal;
  u64 InternalHigh;
  u32 Offset;
  u32 OffsetHigh;
  void* hEvent;
};

// ---------- TLS error & startup state -------------------------------------
__thread i32 t_wsa_err = 0;

void set_wsa_err(i32 e) {
  t_wsa_err = e;
  if (auto fn = (void (TRT_GUEST_ABI*)(u32))trt_resolve_module(
          nullptr, "kernel32.dll", "SetLastError", 0)) {
    fn((u32)e);
  }
}

i32 errno_to_wsa(int e) {
  switch (e) {
    case 0: return 0;
    case EINTR: return 10004;
    case EACCES: return 10013;
    case EFAULT: return 10014;
    case EINVAL: return 10022;
    case EMFILE:
    case ENFILE: return 10024;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
    case EAGAIN: return 10035;
    case EINPROGRESS: return 10036;
    case EALREADY: return 10037;
    case ENOTSOCK:
    case EBADF: return 10038;
    case EDESTADDRREQ: return 10039;
    case EMSGSIZE: return 10040;
    case EPROTOTYPE: return 10041;
    case ENOPROTOOPT: return 10042;
    case EPROTONOSUPPORT: return 10043;
    case ESOCKTNOSUPPORT: return 10044;
    case EOPNOTSUPP: return 10045;
    case EPFNOSUPPORT: return 10046;
    case EAFNOSUPPORT: return 10047;
    case EADDRINUSE: return 10048;
    case EADDRNOTAVAIL: return 10049;
    case ENETDOWN: return 10050;
    case ENETUNREACH: return 10051;
    case ECONNABORTED: return 10053;
    case ECONNRESET:
    case EPIPE: return 10054;
    case ENOBUFS:
    case ENOMEM: return 10055;
    case EISCONN: return 10056;
    case ENOTCONN: return 10057;
    case ESHUTDOWN: return 10058;
    case ETIMEDOUT: return 10060;
    case ECONNREFUSED: return 10061;
    case EHOSTDOWN: return 10064;
    case EHOSTUNREACH: return 10065;
    default: return 10022;
  }
}

int af_win_to_posix(int af) {
  if (af == k_win_af_inet6) return AF_INET6;
  if (af == k_win_af_inet) return AF_INET;
  if (af == k_win_af_unspec) return AF_UNSPEC;
  return af;
}

int af_posix_to_win(int af) {
  if (af == AF_INET6) return k_win_af_inet6;
  if (af == AF_INET) return k_win_af_inet;
  if (af == AF_UNSPEC) return k_win_af_unspec;
  return af;
}

bool sockaddr_win_to_posix(const u8* win_sa, int len,
                           struct sockaddr_storage* out, socklen_t* out_len) {
  if (!win_sa || len < 2 || len > (int)sizeof(*out)) return false;
  memset(out, 0, sizeof(*out));
  memcpy(out, win_sa, (size_t)len);
  u16 win_fam = 0;
  memcpy(&win_fam, win_sa, 2);
  sa_family_t pfam = (sa_family_t)af_win_to_posix((int)win_fam);
  memcpy(out, &pfam, sizeof(pfam));
  *out_len = (socklen_t)len;
  return true;
}

void sockaddr_posix_to_win(const struct sockaddr* in, socklen_t in_len,
                           u8* win_sa, i32* io_len) {
  if (!io_len) return;
  const socklen_t cap = *io_len > 0 ? (socklen_t)*io_len : 0;
  *io_len = (i32)in_len;
  if (!win_sa || !in || cap == 0) return;
  const socklen_t n = in_len < cap ? in_len : cap;
  memcpy(win_sa, in, (size_t)n);
  if (n >= 2) {
    u16 wfam = (u16)af_posix_to_win((int)in->sa_family);
    memcpy(win_sa, &wfam, 2);
  }
}

// ---------- kernel32 event helpers ----------------------------------------
typedef void* (TRT_GUEST_ABI* pfn_CreateEventW)(void*, i32, i32, const u16*);
typedef i32   (TRT_GUEST_ABI* pfn_SetEvent)(void*);
typedef i32   (TRT_GUEST_ABI* pfn_ResetEvent)(void*);
typedef i32   (TRT_GUEST_ABI* pfn_CloseHandle)(void*);
typedef u32   (TRT_GUEST_ABI* pfn_WaitForMultipleObjects)(u32, void* const*, i32, u32);

void* k32_fn(const char* name) {
  return trt_resolve_module(nullptr, "kernel32.dll", name, 0);
}

// ---------- socket metadata (WSAEventSelect + connect tracking) -----------
constexpr int k_max_sock_meta = 4096;
struct sock_meta {
  void* event_handle;
  i32 event_mask;
  bool used;
  bool nonblocking;
  bool connecting;
};

pthread_mutex_t g_sock_mu = PTHREAD_MUTEX_INITIALIZER;
sock_meta g_socks[k_max_sock_meta];

int sock_to_fd(u64 s) {
  if (s == k_invalid_socket || s > 0x7fffffffULL) return -1;
  return (int)s;
}

void sock_meta_init(int fd) {
  if (fd < 0 || fd >= k_max_sock_meta) return;
  pthread_mutex_lock(&g_sock_mu);
  memset(&g_socks[fd], 0, sizeof(g_socks[fd]));
  g_socks[fd].used = true;
  pthread_mutex_unlock(&g_sock_mu);
}

void sock_meta_clear(int fd) {
  if (fd < 0 || fd >= k_max_sock_meta) return;
  pthread_mutex_lock(&g_sock_mu);
  memset(&g_socks[fd], 0, sizeof(g_socks[fd]));
  pthread_mutex_unlock(&g_sock_mu);
}

void sock_set_nonblock_flag(int fd, bool nb) {
  if (fd < 0 || fd >= k_max_sock_meta) return;
  pthread_mutex_lock(&g_sock_mu);
  g_socks[fd].nonblocking = nb;
  pthread_mutex_unlock(&g_sock_mu);
}

// ---------- UTF-16 <-> UTF-8 helpers (BMP/UTF-8 subset) ---------------------
size_t u16_to_utf8(const u16* w, char* out, size_t cap) {
  if (!w || !out || cap == 0) return 0;
  size_t pos = 0;
  for (size_t i = 0; w[i]; ++i) {
    u32 ch = w[i];
    if (ch < 0x80) {
      if (pos + 1 >= cap) break;
      out[pos++] = (char)ch;
    } else if (ch < 0x800) {
      if (pos + 2 >= cap) break;
      out[pos++] = (char)(0xC0 | (ch >> 6));
      out[pos++] = (char)(0x80 | (ch & 0x3F));
    } else {
      if (pos + 3 >= cap) break;
      out[pos++] = (char)(0xE0 | (ch >> 12));
      out[pos++] = (char)(0x80 | ((ch >> 6) & 0x3F));
      out[pos++] = (char)(0x80 | (ch & 0x3F));
    }
  }
  out[pos] = 0;
  return pos;
}

u16* dup_utf8_to_u16(const char* s) {
  if (!s) return nullptr;
  const size_t n = strlen(s);
  u16* w = (u16*)calloc(n + 1, sizeof(u16));
  if (!w) return nullptr;
  size_t out = 0;
  const u8* p = (const u8*)s;
  while (*p) {
    u32 cp = *p++;
    if ((cp & 0xE0) == 0xC0 && (p[0] & 0xC0) == 0x80) {
      cp = ((cp & 0x1F) << 6) | (*p++ & 0x3F);
    } else if ((cp & 0xF0) == 0xE0 && (p[0] & 0xC0) == 0x80 &&
               (p[1] & 0xC0) == 0x80) {
      cp = ((cp & 0x0F) << 12) | ((p[0] & 0x3F) << 6) | (p[1] & 0x3F);
      p += 2;
    } else if (cp >= 0x80) {
      cp = '?';
    }
    w[out++] = (u16)cp;
  }
  w[out] = 0;
  return w;
}

// ---------- thread-local buffers for legacy WS 1.1 getters ----------------
__thread char t_inet_ntoa_buf[32];

struct legacy_hostent_buf {
  win64_hostent ent;
  char name[256];
  char* aliases[1];
  u8 addr4[16][4];
  char* addr_ptrs[17];
};
__thread legacy_hostent_buf t_hostent;

struct legacy_protoent_buf {
  win64_protoent ent;
  char name[64];
  char* aliases[1];
};
__thread legacy_protoent_buf t_protoent;

// ---------- WinSock exports -----------------------------------------------
i32 TRT_GUEST_ABI ws2_WSAStartup(u16 ver, win64_wsadata* data) {
  if (!data) return k_wsa_efault;
  memset(data, 0, sizeof(*data));
  data->wVersion = ver ? ver : 0x0202u;
  data->wHighVersion = 0x0202u;
  data->iMaxSockets = 32767;
  data->iMaxUdpDg = 65467;
  snprintf(data->szDescription, sizeof(data->szDescription), "WinSock 2.0");
  snprintf(data->szSystemStatus, sizeof(data->szSystemStatus), "Running");
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSACleanup(void) {
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSAGetLastError(void) { return t_wsa_err; }

void TRT_GUEST_ABI ws2_WSASetLastError(i32 err) { set_wsa_err(err); }

u64 TRT_GUEST_ABI ws2_socket(i32 af, i32 type, i32 proto) {
  int fd = ::socket(af_win_to_posix(af), type & 0xFF, proto);
  if (fd < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_invalid_socket;
  }
  sock_meta_init(fd);
  set_wsa_err(0);
  return (u64)fd;
}

u64 TRT_GUEST_ABI ws2_WSASocketA(i32 af, i32 type, i32 proto,
                                 void* lpProtocolInfo, u32 g, u32 dwFlags) {
  (void)lpProtocolInfo;
  (void)g;
  (void)dwFlags;
  return ws2_socket(af, type, proto);
}

u64 TRT_GUEST_ABI ws2_WSASocketW(i32 af, i32 type, i32 proto,
                                 void* lpProtocolInfo, u32 g, u32 dwFlags) {
  (void)lpProtocolInfo;
  (void)g;
  (void)dwFlags;
  return ws2_socket(af, type, proto);
}

i32 TRT_GUEST_ABI ws2_closesocket(u64 s) {
  int fd = sock_to_fd(s);
  if (fd < 0) {
    set_wsa_err(k_wsa_enotsock);
    return k_socket_error;
  }
  sock_meta_clear(fd);
  if (::close(fd) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_bind(u64 s, const u8* name, i32 namelen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  if (!sockaddr_win_to_posix(name, namelen, &ss, &slen)) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  if (::bind(fd, (const struct sockaddr*)&ss, slen) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_connect(u64 s, const u8* name, i32 namelen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  if (!sockaddr_win_to_posix(name, namelen, &ss, &slen)) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  if (::connect(fd, (const struct sockaddr*)&ss, slen) < 0) {
    const int e = errno;
    if (e == EINPROGRESS) {
      if (fd < k_max_sock_meta) {
        pthread_mutex_lock(&g_sock_mu);
        g_socks[fd].connecting = true;
        pthread_mutex_unlock(&g_sock_mu);
      }
      // Windows non-blocking connect() reports WSAEWOULDBLOCK, not WSAEINPROGRESS
      set_wsa_err(k_wsa_ewouldblock);
    } else {
      set_wsa_err(errno_to_wsa(e));
    }
    return k_socket_error;
  }
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSAConnect(u64 s, const u8* name, i32 namelen,
                                 void* caller, void* callee,
                                 void* sqos, void* gqos) {
  (void)caller; (void)callee; (void)sqos; (void)gqos;
  return ws2_connect(s, name, namelen);
}

i32 TRT_GUEST_ABI ws2_listen(u64 s, i32 backlog) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (::listen(fd, backlog) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  set_wsa_err(0);
  return 0;
}

u64 TRT_GUEST_ABI ws2_accept(u64 s, u8* addr, i32* addrlen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_invalid_socket; }
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  int cfd = ::accept(fd, addr ? (struct sockaddr*)&ss : nullptr,
                     addr ? &slen : nullptr);
  if (cfd < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_invalid_socket;
  }
  sock_meta_init(cfd);
  if (addr && addrlen) sockaddr_posix_to_win((const struct sockaddr*)&ss, slen, addr, addrlen);
  set_wsa_err(0);
  return (u64)cfd;
}

i32 TRT_GUEST_ABI ws2_shutdown(u64 s, i32 how) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  int phow = (how == 0) ? SHUT_RD : (how == 1) ? SHUT_WR : SHUT_RDWR;
  if (::shutdown(fd, phow) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_send(u64 s, const char* buf, i32 len, i32 flags) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  ssize_t r = ::send(fd, buf, (size_t)len, flags | MSG_NOSIGNAL);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  set_wsa_err(0);
  return (i32)r;
}

i32 TRT_GUEST_ABI ws2_recv(u64 s, char* buf, i32 len, i32 flags) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  ssize_t r = ::recv(fd, buf, (size_t)len, flags);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  set_wsa_err(0);
  return (i32)r;
}

i32 TRT_GUEST_ABI ws2_sendto(u64 s, const char* buf, i32 len, i32 flags,
                             const u8* to, i32 tolen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  const struct sockaddr* psa = nullptr;
  if (to && tolen > 0) {
    if (!sockaddr_win_to_posix(to, tolen, &ss, &slen)) {
      set_wsa_err(k_wsa_einval);
      return k_socket_error;
    }
    psa = (const struct sockaddr*)&ss;
  }
  ssize_t r = ::sendto(fd, buf, (size_t)len, flags | MSG_NOSIGNAL, psa, slen);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  set_wsa_err(0);
  return (i32)r;
}

i32 TRT_GUEST_ABI ws2_recvfrom(u64 s, char* buf, i32 len, i32 flags,
                               u8* from, i32* fromlen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  ssize_t r = ::recvfrom(fd, buf, (size_t)len, flags,
                         from ? (struct sockaddr*)&ss : nullptr,
                         from ? &slen : nullptr);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  if (from && fromlen) sockaddr_posix_to_win((const struct sockaddr*)&ss, slen, from, fromlen);
  set_wsa_err(0);
  return (i32)r;
}

i32 TRT_GUEST_ABI ws2_WSASend(u64 s, const win64_wsabuf* bufs, u32 count,
                              u32* sent, u32 flags, void* ov, void* comp) {
  (void)ov; (void)comp;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (!bufs || count == 0 || count > 1024) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  struct iovec iov[64];
  const u32 n = count < 64 ? count : 64;
  for (u32 i = 0; i < n; ++i) {
    iov[i].iov_base = bufs[i].buf;
    iov[i].iov_len = bufs[i].len;
  }
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = n;
  ssize_t r = ::sendmsg(fd, &msg, (int)flags | MSG_NOSIGNAL);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  if (sent) *sent = (u32)r;
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSARecv(u64 s, const win64_wsabuf* bufs, u32 count,
                              u32* recvd, u32* flags, void* ov, void* comp) {
  (void)ov; (void)comp;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (!bufs || count == 0 || count > 1024) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  struct iovec iov[64];
  const u32 n = count < 64 ? count : 64;
  for (u32 i = 0; i < n; ++i) {
    iov[i].iov_base = bufs[i].buf;
    iov[i].iov_len = bufs[i].len;
  }
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_iov = iov;
  msg.msg_iovlen = n;
  int iflags = flags ? (int)*flags : 0;
  ssize_t r = ::recvmsg(fd, &msg, iflags);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  if (recvd) *recvd = (u32)r;
  if (flags) *flags = (u32)msg.msg_flags;
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSASendDisconnect(u64 s, void* out_data) {
  (void)out_data;
  return ws2_shutdown(s, 1);
}

i32 TRT_GUEST_ABI ws2_getsockname(u64 s, u8* name, i32* namelen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  if (::getsockname(fd, (struct sockaddr*)&ss, &slen) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  sockaddr_posix_to_win((const struct sockaddr*)&ss, slen, name, namelen);
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_getpeername(u64 s, u8* name, i32* namelen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  struct sockaddr_storage ss;
  socklen_t slen = sizeof(ss);
  if (::getpeername(fd, (struct sockaddr*)&ss, &slen) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  sockaddr_posix_to_win((const struct sockaddr*)&ss, slen, name, namelen);
  set_wsa_err(0);
  return 0;
}

bool map_sockopt(i32 wlevel, i32 wopt, int* plevel, int* popt) {
  if (wlevel == k_win_sol_socket) {
    *plevel = SOL_SOCKET;
    switch (wopt) {
      case k_win_so_reuseaddr: *popt = SO_REUSEADDR; return true;
      case k_win_so_keepalive: *popt = SO_KEEPALIVE; return true;
      case k_win_so_broadcast: *popt = SO_BROADCAST; return true;
      case k_win_so_linger:    *popt = SO_LINGER;    return true;
      case k_win_so_sndbuf:    *popt = SO_SNDBUF;    return true;
      case k_win_so_rcvbuf:    *popt = SO_RCVBUF;    return true;
      case k_win_so_sndtimeo:  *popt = SO_SNDTIMEO;  return true;
      case k_win_so_rcvtimeo:  *popt = SO_RCVTIMEO;  return true;
      case k_win_so_error:     *popt = SO_ERROR;     return true;
      default: return false;
    }
  }
  if (wlevel == k_win_ipproto_tcp) {
    *plevel = IPPROTO_TCP;
    if (wopt == k_win_tcp_nodelay) { *popt = TCP_NODELAY; return true; }
    return false;
  }
  if (wlevel == k_win_ipproto_ipv6) {
    *plevel = IPPROTO_IPV6;
    if (wopt == k_win_ipv6_v6only) { *popt = IPV6_V6ONLY; return true; }
    return false;
  }
  *plevel = wlevel;
  *popt = wopt;
  return true;
}

i32 TRT_GUEST_ABI ws2_setsockopt(u64 s, i32 level, i32 optname,
                                 const char* optval, i32 optlen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  int plevel = 0, popt = 0;
  if (!map_sockopt(level, optname, &plevel, &popt)) {
    set_wsa_err(0);
    return 0;
  }
  if (level == k_win_sol_socket &&
      (optname == k_win_so_sndtimeo || optname == k_win_so_rcvtimeo) &&
      optval && optlen >= 4) {
    u32 ms = 0;
    memcpy(&ms, optval, 4);
    struct timeval tv;
    tv.tv_sec = (time_t)(ms / 1000u);
    tv.tv_usec = (suseconds_t)((ms % 1000u) * 1000u);
    if (::setsockopt(fd, plevel, popt, &tv, sizeof(tv)) < 0) {
      set_wsa_err(errno_to_wsa(errno));
      return k_socket_error;
    }
    set_wsa_err(0);
    return 0;
  }
  if (::setsockopt(fd, plevel, popt, optval, (socklen_t)optlen) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_getsockopt(u64 s, i32 level, i32 optname,
                                 char* optval, i32* optlen) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (!optval || !optlen) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  int plevel = 0, popt = 0;
  if (!map_sockopt(level, optname, &plevel, &popt)) {
    set_wsa_err(10042 /*WSAENOPROTOOPT*/);
    return k_socket_error;
  }
  socklen_t slen = (socklen_t)*optlen;
  if (::getsockopt(fd, plevel, popt, optval, &slen) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  if (level == k_win_sol_socket && optname == k_win_so_error && slen >= 4) {
    i32 perr = 0;
    memcpy(&perr, optval, 4);
    i32 werr = errno_to_wsa(perr);
    memcpy(optval, &werr, 4);
  }
  *optlen = (i32)slen;
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_ioctlsocket(u64 s, i32 cmd, u32* argp) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (!argp) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  const u32 ucmd = (u32)cmd;
  if (ucmd == k_win_fionbio) {
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
    if (*argp) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    if (::fcntl(fd, F_SETFL, flags) < 0) {
      set_wsa_err(errno_to_wsa(errno));
      return k_socket_error;
    }
    sock_set_nonblock_flag(fd, *argp != 0);
    set_wsa_err(0);
    return 0;
  }
  if (ucmd == k_win_fionread) {
    int n = 0;
    if (::ioctl(fd, FIONREAD, &n) < 0) {
      set_wsa_err(errno_to_wsa(errno));
      return k_socket_error;
    }
    *argp = n < 0 ? 0u : (u32)n;
    set_wsa_err(0);
    return 0;
  }
  set_wsa_err(k_wsa_einval);
  return k_socket_error;
}

i32 TRT_GUEST_ABI ws2___WSAFDIsSet(u64 fd, const win64_fd_set* set) {
  if (!set) return 0;
  const u32 n = set->fd_count < 64 ? set->fd_count : 64;
  for (u32 i = 0; i < n; ++i)
    if (set->fd_array[i] == fd) return 1;
  return 0;
}

i32 TRT_GUEST_ABI ws2_select(i32 nfds, win64_fd_set* readfds,
                             win64_fd_set* writefds, win64_fd_set* exceptfds,
                             const win64_timeval* timeout) {
  (void)nfds;
  fd_set rfds, wfds, efds;
  FD_ZERO(&rfds); FD_ZERO(&wfds); FD_ZERO(&efds);
  int maxfd = -1;
  auto add_set = [&](const win64_fd_set* w, fd_set* p) {
    if (!w) return;
    const u32 n = w->fd_count < 64 ? w->fd_count : 64;
    for (u32 i = 0; i < n; ++i) {
      int fd = sock_to_fd(w->fd_array[i]);
      if (fd >= 0 && fd < FD_SETSIZE) {
        FD_SET(fd, p);
        if (fd > maxfd) maxfd = fd;
      }
    }
  };
  add_set(readfds, &rfds);
  add_set(writefds, &wfds);
  add_set(exceptfds, &efds);

  struct timeval tv;
  struct timeval* ptv = nullptr;
  if (timeout) {
    tv.tv_sec = timeout->tv_sec;
    tv.tv_usec = timeout->tv_usec;
    ptv = &tv;
  }
  int r = ::select(maxfd + 1, readfds ? &rfds : nullptr,
                   writefds ? &wfds : nullptr, exceptfds ? &efds : nullptr,
                   ptv);
  if (r < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  auto filter_set = [](win64_fd_set* w, const fd_set* p) {
    if (!w) return;
    u32 out = 0;
    const u32 n = w->fd_count < 64 ? w->fd_count : 64;
    for (u32 i = 0; i < n; ++i) {
      int fd = sock_to_fd(w->fd_array[i]);
      if (fd >= 0 && fd < FD_SETSIZE && FD_ISSET(fd, p))
        w->fd_array[out++] = w->fd_array[i];
    }
    w->fd_count = out;
  };
  filter_set(readfds, &rfds);
  filter_set(writefds, &wfds);
  filter_set(exceptfds, &efds);
  set_wsa_err(0);
  return r;
}

i32 TRT_GUEST_ABI ws2_WSAPoll(win64_pollfd* fdArray, u32 fds, i32 timeout) {
  if (!fdArray && fds > 0) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  struct pollfd pfds[256];
  const u32 n = fds < 256 ? fds : 256;
  for (u32 i = 0; i < n; ++i) {
    pfds[i].fd = sock_to_fd(fdArray[i].fd);
    short pev = 0;
    const i16 wev = fdArray[i].events;
    if (wev & (k_win_pollrdnorm | k_win_pollrdband)) pev |= POLLIN;
    if (wev & k_win_pollwrnorm) pev |= POLLOUT;
    pfds[i].events = pev;
    pfds[i].revents = 0;
    fdArray[i].revents = 0;
  }
  int r = ::poll(pfds, n, timeout);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  for (u32 i = 0; i < n; ++i) {
    i16 wrev = 0;
    const short pr = pfds[i].revents;
    if (pr & POLLIN) wrev |= k_win_pollrdnorm;
    if (pr & POLLPRI) wrev |= k_win_pollrdband;
    if (pr & POLLOUT) wrev |= k_win_pollwrnorm;
    if (pr & POLLERR) wrev |= k_win_pollerr;
    if (pr & POLLHUP) wrev |= k_win_pollhup;
    if (pr & POLLNVAL) wrev |= k_win_pollnval;
    fdArray[i].revents = wrev;
  }
  set_wsa_err(0);
  return r;
}

u32 TRT_GUEST_ABI ws2_htonl(u32 v) { return htonl(v); }
u16 TRT_GUEST_ABI ws2_htons(u16 v) { return htons(v); }
u32 TRT_GUEST_ABI ws2_ntohl(u32 v) { return ntohl(v); }
u16 TRT_GUEST_ABI ws2_ntohs(u16 v) { return ntohs(v); }

i32 TRT_GUEST_ABI ws2_WSAHtonl(u64 s, u32 hostlong, u32* lpnetlong) {
  (void)s;
  if (!lpnetlong) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  *lpnetlong = htonl(hostlong);
  return 0;
}
i32 TRT_GUEST_ABI ws2_WSAHtons(u64 s, u16 hostshort, u16* lpnetshort) {
  (void)s;
  if (!lpnetshort) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  *lpnetshort = htons(hostshort);
  return 0;
}
i32 TRT_GUEST_ABI ws2_WSANtohl(u64 s, u32 netlong, u32* lphostlong) {
  (void)s;
  if (!lphostlong) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  *lphostlong = ntohl(netlong);
  return 0;
}
i32 TRT_GUEST_ABI ws2_WSANtohs(u64 s, u16 netshort, u16* lphostshort) {
  (void)s;
  if (!lphostshort) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  *lphostshort = ntohs(netshort);
  return 0;
}

u32 TRT_GUEST_ABI ws2_inet_addr(const char* cp) {
  if (!cp) return 0xFFFFFFFFu;
  return (u32)::inet_addr(cp);
}

char* TRT_GUEST_ABI ws2_inet_ntoa(u32 in_addr_v) {
  struct in_addr a;
  a.s_addr = in_addr_v;
  const char* s = ::inet_ntoa(a);
  if (!s) return nullptr;
  snprintf(t_inet_ntoa_buf, sizeof(t_inet_ntoa_buf), "%s", s);
  return t_inet_ntoa_buf;
}

i32 TRT_GUEST_ABI ws2_inet_pton(i32 af, const char* src, void* dst) {
  int r = ::inet_pton(af_win_to_posix(af), src, dst);
  if (r < 0) set_wsa_err(errno_to_wsa(errno));
  return (i32)r;
}

const char* TRT_GUEST_ABI ws2_inet_ntop(i32 af, const void* src, char* dst, u64 size) {
  const char* r = ::inet_ntop(af_win_to_posix(af), src, dst, (socklen_t)size);
  if (!r) set_wsa_err(errno_to_wsa(errno));
  return r;
}

i32 TRT_GUEST_ABI ws2_InetPtonW(i32 af, const u16* src, void* dst) {
  if (!src) { set_wsa_err(k_wsa_efault); return -1; }
  char buf[128];
  u16_to_utf8(src, buf, sizeof(buf));
  return ws2_inet_pton(af, buf, dst);
}

const u16* TRT_GUEST_ABI ws2_InetNtopW(i32 af, const void* src, u16* dst, u64 cnt) {
  if (!dst || cnt == 0) { set_wsa_err(k_wsa_efault); return nullptr; }
  char buf[128];
  if (!ws2_inet_ntop(af, src, buf, sizeof(buf))) return nullptr;
  size_t i = 0;
  for (; buf[i] && i + 1 < cnt; ++i) dst[i] = (u16)(u8)buf[i];
  dst[i] = 0;
  return dst;
}

// ---------- getaddrinfo / GetAddrInfoW / GetAddrInfoExW -------------------
int gai_err_to_wsa(int e) {
  switch (e) {
    case 0: return 0;
    case EAI_AGAIN: return 11002;
    case EAI_FAIL: return 11003;
    case EAI_NONAME: return 11001;
    case EAI_SERVICE: return 10109;
    case EAI_FAMILY: return 10047;
    case EAI_SOCKTYPE: return 10044;
    case EAI_MEMORY: return 8;
    default: return 11001;
  }
}

void build_posix_hints(i32 flags, i32 family, i32 socktype, i32 protocol,
                       struct addrinfo* out) {
  memset(out, 0, sizeof(*out));
  out->ai_flags = flags;
  out->ai_family = af_win_to_posix(family);
  out->ai_socktype = socktype;
  out->ai_protocol = protocol;
}

win64_addrinfo_a* alloc_win64_ai_a(const struct addrinfo* src) {
  win64_addrinfo_a* head = nullptr;
  win64_addrinfo_a* tail = nullptr;
  for (const struct addrinfo* cur = src; cur; cur = cur->ai_next) {
    win64_addrinfo_a* node = (win64_addrinfo_a*)calloc(1, sizeof(*node));
    if (!node) break;
    node->ai_flags = cur->ai_flags;
    node->ai_family = af_posix_to_win(cur->ai_family);
    node->ai_socktype = cur->ai_socktype;
    node->ai_protocol = cur->ai_protocol;
    node->ai_addrlen = (u64)cur->ai_addrlen;
    if (cur->ai_canonname) node->ai_canonname = strdup(cur->ai_canonname);
    if (cur->ai_addr && cur->ai_addrlen > 0) {
      node->ai_addr = (u8*)malloc(cur->ai_addrlen);
      if (node->ai_addr) {
        i32 alen = (i32)cur->ai_addrlen;
        sockaddr_posix_to_win(cur->ai_addr, cur->ai_addrlen, node->ai_addr, &alen);
      }
    }
    if (!head) head = node;
    else tail->ai_next = node;
    tail = node;
  }
  return head;
}

win64_addrinfo_w* alloc_win64_ai_w(const struct addrinfo* src) {
  win64_addrinfo_w* head = nullptr;
  win64_addrinfo_w* tail = nullptr;
  for (const struct addrinfo* cur = src; cur; cur = cur->ai_next) {
    win64_addrinfo_w* node = (win64_addrinfo_w*)calloc(1, sizeof(*node));
    if (!node) break;
    node->ai_flags = cur->ai_flags;
    node->ai_family = af_posix_to_win(cur->ai_family);
    node->ai_socktype = cur->ai_socktype;
    node->ai_protocol = cur->ai_protocol;
    node->ai_addrlen = (u64)cur->ai_addrlen;
    if (cur->ai_canonname) node->ai_canonname = dup_utf8_to_u16(cur->ai_canonname);
    if (cur->ai_addr && cur->ai_addrlen > 0) {
      node->ai_addr = (u8*)malloc(cur->ai_addrlen);
      if (node->ai_addr) {
        i32 alen = (i32)cur->ai_addrlen;
        sockaddr_posix_to_win(cur->ai_addr, cur->ai_addrlen, node->ai_addr, &alen);
      }
    }
    if (!head) head = node;
    else tail->ai_next = node;
    tail = node;
  }
  return head;
}

win64_addrinfo_exw* alloc_win64_ai_exw(const struct addrinfo* src) {
  win64_addrinfo_exw* head = nullptr;
  win64_addrinfo_exw* tail = nullptr;
  for (const struct addrinfo* cur = src; cur; cur = cur->ai_next) {
    win64_addrinfo_exw* node = (win64_addrinfo_exw*)calloc(1, sizeof(*node));
    if (!node) break;
    node->ai_flags = cur->ai_flags;
    node->ai_family = af_posix_to_win(cur->ai_family);
    node->ai_socktype = cur->ai_socktype;
    node->ai_protocol = cur->ai_protocol;
    node->ai_addrlen = (u64)cur->ai_addrlen;
    if (cur->ai_canonname) node->ai_canonname = dup_utf8_to_u16(cur->ai_canonname);
    if (cur->ai_addr && cur->ai_addrlen > 0) {
      node->ai_addr = (u8*)malloc(cur->ai_addrlen);
      if (node->ai_addr) {
        i32 alen = (i32)cur->ai_addrlen;
        sockaddr_posix_to_win(cur->ai_addr, cur->ai_addrlen, node->ai_addr, &alen);
      }
    }
    if (!head) head = node;
    else tail->ai_next = node;
    tail = node;
  }
  return head;
}

i32 TRT_GUEST_ABI ws2_getaddrinfo(const char* node, const char* service,
                                  const win64_addrinfo_a* hints,
                                  win64_addrinfo_a** res) {
  if (!res) return k_wsa_efault;
  *res = nullptr;
  struct addrinfo phints;
  if (hints) {
    build_posix_hints(hints->ai_flags, hints->ai_family,
                      hints->ai_socktype, hints->ai_protocol, &phints);
  }
  struct addrinfo* pres = nullptr;
  int r = ::getaddrinfo(node, service, hints ? &phints : nullptr, &pres);
  if (r != 0) {
    int w = gai_err_to_wsa(r);
    set_wsa_err(w);
    return w;
  }
  *res = alloc_win64_ai_a(pres);
  ::freeaddrinfo(pres);
  set_wsa_err(0);
  return 0;
}

void TRT_GUEST_ABI ws2_freeaddrinfo(win64_addrinfo_a* ai) {
  while (ai) {
    win64_addrinfo_a* nxt = ai->ai_next;
    free(ai->ai_canonname);
    free(ai->ai_addr);
    free(ai);
    ai = nxt;
  }
}

i32 TRT_GUEST_ABI ws2_GetAddrInfoW(const u16* node, const u16* service,
                                   const win64_addrinfo_w* hints,
                                   win64_addrinfo_w** res) {
  if (!res) return k_wsa_efault;
  *res = nullptr;
  char nbuf[512], sbuf[128];
  if (node) u16_to_utf8(node, nbuf, sizeof(nbuf));
  if (service) u16_to_utf8(service, sbuf, sizeof(sbuf));
  struct addrinfo phints;
  if (hints) {
    build_posix_hints(hints->ai_flags, hints->ai_family,
                      hints->ai_socktype, hints->ai_protocol, &phints);
  }
  struct addrinfo* pres = nullptr;
  int r = ::getaddrinfo(node ? nbuf : nullptr, service ? sbuf : nullptr,
                        hints ? &phints : nullptr, &pres);
  if (r != 0) {
    int w = gai_err_to_wsa(r);
    set_wsa_err(w);
    return w;
  }
  *res = alloc_win64_ai_w(pres);
  ::freeaddrinfo(pres);
  set_wsa_err(0);
  return 0;
}

void TRT_GUEST_ABI ws2_FreeAddrInfoW(win64_addrinfo_w* ai) {
  while (ai) {
    win64_addrinfo_w* nxt = ai->ai_next;
    free(ai->ai_canonname);
    free(ai->ai_addr);
    free(ai);
    ai = nxt;
  }
}

i32 TRT_GUEST_ABI ws2_GetAddrInfoExW(const u16* pName, const u16* pServiceName,
                                     u32 dwNameSpace, void* lpNspId,
                                     const win64_addrinfo_exw* hints,
                                     win64_addrinfo_exw** ppResult,
                                     void* timeout, win64_overlapped* lpOverlapped,
                                     void* lpCompletionRoutine, void** lpHandle) {
  (void)dwNameSpace; (void)lpNspId; (void)timeout; (void)lpCompletionRoutine;
  if (!ppResult) return k_wsa_efault;
  *ppResult = nullptr;
  if (lpHandle) *lpHandle = nullptr;
  char nbuf[512], sbuf[128];
  if (pName) u16_to_utf8(pName, nbuf, sizeof(nbuf));
  if (pServiceName) u16_to_utf8(pServiceName, sbuf, sizeof(sbuf));
  struct addrinfo phints;
  if (hints) {
    build_posix_hints(hints->ai_flags, hints->ai_family,
                      hints->ai_socktype, hints->ai_protocol, &phints);
  }
  struct addrinfo* pres = nullptr;
  int r = ::getaddrinfo(pName ? nbuf : nullptr, pServiceName ? sbuf : nullptr,
                        hints ? &phints : nullptr, &pres);
  if (r != 0) {
    int w = gai_err_to_wsa(r);
    set_wsa_err(w);
    return w;
  }
  *ppResult = alloc_win64_ai_exw(pres);
  ::freeaddrinfo(pres);
  if (lpOverlapped) {
    lpOverlapped->Internal = 0;
    if (lpOverlapped->hEvent) {
      if (auto fn = (pfn_SetEvent)k32_fn("SetEvent")) fn(lpOverlapped->hEvent);
    }
  }
  set_wsa_err(0);
  return 0;  // completed synchronously
}

void TRT_GUEST_ABI ws2_FreeAddrInfoExW(win64_addrinfo_exw* ai) {
  while (ai) {
    win64_addrinfo_exw* nxt = ai->ai_next;
    free(ai->ai_canonname);
    free(ai->ai_addr);
    free(ai);
    ai = nxt;
  }
}

i32 TRT_GUEST_ABI ws2_GetAddrInfoExCancel(void** lpHandle) {
  (void)lpHandle;
  return 0;
}

i32 TRT_GUEST_ABI ws2_getnameinfo(const u8* sa, i32 salen,
                                  char* host, u32 hostlen,
                                  char* serv, u32 servlen, i32 flags) {
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  if (!sockaddr_win_to_posix(sa, salen, &ss, &slen)) {
    set_wsa_err(k_wsa_einval);
    return k_wsa_einval;
  }
  int r = ::getnameinfo((const struct sockaddr*)&ss, slen,
                        host, (socklen_t)hostlen,
                        serv, (socklen_t)servlen, flags);
  if (r != 0) {
    int w = gai_err_to_wsa(r);
    set_wsa_err(w);
    return w;
  }
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_GetNameInfoW(const u8* sa, i32 salen,
                                   u16* host, u32 hostlen,
                                   u16* serv, u32 servlen, i32 flags) {
  char hbuf[256] = {0}, sbuf[64] = {0};
  i32 r = ws2_getnameinfo(sa, salen, host ? hbuf : nullptr, sizeof(hbuf),
                          serv ? sbuf : nullptr, sizeof(sbuf), flags);
  if (r != 0) return r;
  if (host && hostlen) {
    size_t i = 0;
    for (; hbuf[i] && i + 1 < hostlen; ++i) host[i] = (u16)(u8)hbuf[i];
    host[i] = 0;
  }
  if (serv && servlen) {
    size_t i = 0;
    for (; sbuf[i] && i + 1 < servlen; ++i) serv[i] = (u16)(u8)sbuf[i];
    serv[i] = 0;
  }
  return 0;
}

i32 TRT_GUEST_ABI ws2_gethostname(char* name, i32 namelen) {
  if (!name || namelen <= 0) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  if (::gethostname(name, (size_t)namelen) < 0) {
    set_wsa_err(errno_to_wsa(errno));
    return k_socket_error;
  }
  name[namelen - 1] = 0;
  set_wsa_err(0);
  return 0;
}

win64_hostent* fill_hostent_from_ai(const char* name, const struct addrinfo* res) {
  memset(&t_hostent, 0, sizeof(t_hostent));
  snprintf(t_hostent.name, sizeof(t_hostent.name), "%s",
           (res && res->ai_canonname) ? res->ai_canonname : (name ? name : ""));
  t_hostent.ent.h_name = t_hostent.name;
  t_hostent.aliases[0] = nullptr;
  t_hostent.ent.h_aliases = t_hostent.aliases;
  t_hostent.ent.h_addrtype = (i16)k_win_af_inet;
  t_hostent.ent.h_length = 4;
  int count = 0;
  for (const struct addrinfo* cur = res; cur && count < 16; cur = cur->ai_next) {
    if (cur->ai_family == AF_INET && cur->ai_addr) {
      const struct sockaddr_in* in = (const struct sockaddr_in*)cur->ai_addr;
      memcpy(t_hostent.addr4[count], &in->sin_addr, 4);
      t_hostent.addr_ptrs[count] = (char*)t_hostent.addr4[count];
      ++count;
    }
  }
  t_hostent.addr_ptrs[count] = nullptr;
  t_hostent.ent.h_addr_list = t_hostent.addr_ptrs;
  return count > 0 ? &t_hostent.ent : nullptr;
}

win64_hostent* TRT_GUEST_ABI ws2_gethostbyname(const char* name) {
  if (!name) { set_wsa_err(k_wsa_efault); return nullptr; }
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  hints.ai_flags = AI_CANONNAME;
  struct addrinfo* res = nullptr;
  int r = ::getaddrinfo(name, nullptr, &hints, &res);
  if (r != 0) { set_wsa_err(gai_err_to_wsa(r)); return nullptr; }
  win64_hostent* he = fill_hostent_from_ai(name, res);
  ::freeaddrinfo(res);
  if (!he) { set_wsa_err(k_wsa_host_not_found); return nullptr; }
  set_wsa_err(0);
  return he;
}

win64_hostent* TRT_GUEST_ABI ws2_gethostbyaddr(const char* addr, i32 len, i32 type) {
  if (!addr || len != 4 || af_win_to_posix(type) != AF_INET) {
    set_wsa_err(k_wsa_host_not_found);
    return nullptr;
  }
  memset(&t_hostent, 0, sizeof(t_hostent));
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  memcpy(&sin.sin_addr, addr, 4);
  if (::getnameinfo((const struct sockaddr*)&sin, sizeof(sin),
                    t_hostent.name, sizeof(t_hostent.name), nullptr, 0, 0) != 0) {
    snprintf(t_hostent.name, sizeof(t_hostent.name), "host");
  }
  t_hostent.ent.h_name = t_hostent.name;
  t_hostent.aliases[0] = nullptr;
  t_hostent.ent.h_aliases = t_hostent.aliases;
  t_hostent.ent.h_addrtype = (i16)k_win_af_inet;
  t_hostent.ent.h_length = 4;
  memcpy(t_hostent.addr4[0], addr, 4);
  t_hostent.addr_ptrs[0] = (char*)t_hostent.addr4[0];
  t_hostent.addr_ptrs[1] = nullptr;
  t_hostent.ent.h_addr_list = t_hostent.addr_ptrs;
  set_wsa_err(0);
  return &t_hostent.ent;
}

win64_protoent* TRT_GUEST_ABI ws2_getprotobyname(const char* name) {
  if (!name) { set_wsa_err(k_wsa_efault); return nullptr; }
  struct protoent* p = ::getprotobyname(name);
  if (!p) { set_wsa_err(11004 /*WSANO_DATA*/); return nullptr; }
  memset(&t_protoent, 0, sizeof(t_protoent));
  snprintf(t_protoent.name, sizeof(t_protoent.name), "%s", p->p_name ? p->p_name : name);
  t_protoent.ent.p_name = t_protoent.name;
  t_protoent.aliases[0] = nullptr;
  t_protoent.ent.p_aliases = t_protoent.aliases;
  t_protoent.ent.p_proto = (i16)p->p_proto;
  set_wsa_err(0);
  return &t_protoent.ent;
}

// ---------- WSA Events, WSAEventSelect, WSAWaitForMultipleEvents ----------
void* TRT_GUEST_ABI ws2_WSACreateEvent(void) {
  auto fn = (pfn_CreateEventW)k32_fn("CreateEventW");
  if (!fn) { set_wsa_err(k_wsa_eopnotsupp); return nullptr; }
  void* h = fn(nullptr, 1 /*manual reset*/, 0 /*unsignaled*/, nullptr);
  set_wsa_err(h ? 0 : 8);
  return h;
}

i32 TRT_GUEST_ABI ws2_WSACloseEvent(void* hEvent) {
  if (hEvent) {
    pthread_mutex_lock(&g_sock_mu);
    for (int i = 0; i < k_max_sock_meta; ++i) {
      if (g_socks[i].used && g_socks[i].event_handle == hEvent) {
        g_socks[i].event_handle = nullptr;
        g_socks[i].event_mask = 0;
      }
    }
    pthread_mutex_unlock(&g_sock_mu);
  }
  auto fn = (pfn_CloseHandle)k32_fn("CloseHandle");
  if (!fn) return 0;
  return fn(hEvent);
}

i32 TRT_GUEST_ABI ws2_WSASetEvent(void* hEvent) {
  auto fn = (pfn_SetEvent)k32_fn("SetEvent");
  return fn ? fn(hEvent) : 0;
}

i32 TRT_GUEST_ABI ws2_WSAResetEvent(void* hEvent) {
  auto fn = (pfn_ResetEvent)k32_fn("ResetEvent");
  return fn ? fn(hEvent) : 0;
}

i32 TRT_GUEST_ABI ws2_WSAEventSelect(u64 s, void* hEventObject, i32 lNetworkEvents) {
  int fd = sock_to_fd(s);
  if (fd < 0 || fd >= k_max_sock_meta) {
    set_wsa_err(k_wsa_enotsock);
    return k_socket_error;
  }
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  pthread_mutex_lock(&g_sock_mu);
  g_socks[fd].used = true;
  g_socks[fd].nonblocking = true;
  g_socks[fd].event_handle = hEventObject;
  g_socks[fd].event_mask = lNetworkEvents;
  pthread_mutex_unlock(&g_sock_mu);
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSAEnumNetworkEvents(u64 s, void* hEventObject,
                                           win64_network_events* out) {
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (!out) { set_wsa_err(k_wsa_efault); return k_socket_error; }
  memset(out, 0, sizeof(*out));
  if (hEventObject) ws2_WSAResetEvent(hEventObject);

  i32 mask = k_fd_read | k_fd_write | k_fd_connect | k_fd_close;
  bool was_conn = false;
  if (fd < k_max_sock_meta) {
    pthread_mutex_lock(&g_sock_mu);
    if (g_socks[fd].event_mask) mask = g_socks[fd].event_mask;
    was_conn = g_socks[fd].connecting;
    g_socks[fd].connecting = false;
    pthread_mutex_unlock(&g_sock_mu);
  }
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN | POLLOUT;
  pfd.revents = 0;
  if (::poll(&pfd, 1, 0) > 0) {
    int serr = 0;
    socklen_t slen = sizeof(serr);
    if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &serr, &slen) < 0) serr = errno;
    i32 werr = errno_to_wsa(serr);
    if (was_conn && (mask & k_fd_connect) &&
        (pfd.revents & (POLLOUT | POLLERR | POLLHUP))) {
      out->lNetworkEvents |= k_fd_connect;
      out->iErrorCode[4] = werr;
    }
    if ((pfd.revents & POLLIN) && (mask & (k_fd_read | k_fd_accept))) {
      char tmp = 0;
      ssize_t pk = ::recv(fd, &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
      if (pk == 0 && (mask & k_fd_close)) {
        out->lNetworkEvents |= k_fd_close;
        out->iErrorCode[5] = werr;
      } else {
        i32 bit = (mask & k_fd_accept) ? k_fd_accept : k_fd_read;
        out->lNetworkEvents |= bit;
        out->iErrorCode[(bit == k_fd_accept) ? 3 : 0] = werr;
      }
    }
    if ((pfd.revents & POLLOUT) && (mask & k_fd_write) && werr == 0) {
      out->lNetworkEvents |= k_fd_write;
      out->iErrorCode[1] = 0;
    }
    if ((pfd.revents & (POLLHUP | POLLERR)) && (mask & k_fd_close)) {
      out->lNetworkEvents |= k_fd_close;
      out->iErrorCode[5] = werr;
    }
  }
  set_wsa_err(0);
  return 0;
}

u32 TRT_GUEST_ABI ws2_WSAWaitForMultipleEvents(u32 cEvents, void* const* lphEvents,
                                               i32 fWaitAll, u32 dwTimeout,
                                               i32 fAlertable) {
  (void)fAlertable;
  auto wait_fn = (pfn_WaitForMultipleObjects)k32_fn("WaitForMultipleObjects");
  if (!wait_fn || cEvents == 0 || !lphEvents) return 0xFFFFFFFFu;

  // Check if any requested events are currently bound to sockets via WSAEventSelect.
  struct pollfd pfds[64];
  u32 pfd_ev_idx[64];
  int npfds = 0;
  pthread_mutex_lock(&g_sock_mu);
  for (int fd = 0; fd < k_max_sock_meta && npfds < 64; ++fd) {
    if (!g_socks[fd].used || !g_socks[fd].event_handle) continue;
    for (u32 i = 0; i < cEvents; ++i) {
      if (lphEvents[i] == g_socks[fd].event_handle) {
        short pev = 0;
        const i32 m = g_socks[fd].event_mask;
        if (m & (k_fd_read | k_fd_accept | k_fd_close)) pev |= POLLIN;
        if (m & (k_fd_write | k_fd_connect)) pev |= POLLOUT;
        pfds[npfds].fd = fd;
        pfds[npfds].events = pev;
        pfds[npfds].revents = 0;
        pfd_ev_idx[npfds] = i;
        ++npfds;
        break;
      }
    }
  }
  pthread_mutex_unlock(&g_sock_mu);

  if (npfds == 0) {
    return wait_fn(cEvents, (void**)lphEvents, fWaitAll, dwTimeout);
  }
  u32 w0 = wait_fn(cEvents, (void**)lphEvents, fWaitAll, 0);
  if (w0 != 0x102u /*WAIT_TIMEOUT*/) return w0;

  const int ms = (dwTimeout == 0xFFFFFFFFu) ? -1 : (int)dwTimeout;
  int pr = ::poll(pfds, (nfds_t)npfds, ms);
  if (pr > 0) {
    for (int k = 0; k < npfds; ++k) {
      if (pfds[k].revents) return pfd_ev_idx[k];
    }
  }
  return wait_fn(cEvents, (void**)lphEvents, fWaitAll, 0);
}

struct win64_wsamsg {
  u8* name;
  i32 namelen;
  u32 _pad0;
  win64_wsabuf* lpBuffers;
  u32 dwBufferCount;
  u32 _pad1;
  win64_wsabuf Control;
  u32 dwFlags;
  u32 _pad2;
};

i32 TRT_GUEST_ABI ws2_ConnectEx(u64, const u8*, i32, void*, u32, u32*, win64_overlapped*);
i32 TRT_GUEST_ABI ws2_AcceptEx(u64, u64, u8*, u32, u32, u32, u32*, win64_overlapped*);
void TRT_GUEST_ABI ws2_GetAcceptExSockaddrs(u8*, u32, u32, u32, u8**, i32*, u8**, i32*);
i32 TRT_GUEST_ABI ws2_DisconnectEx(u64, win64_overlapped*, u32, u32);
i32 TRT_GUEST_ABI ws2_TransmitFile(u64, void*, u32, u32, win64_overlapped*, void*, u32);
i32 TRT_GUEST_ABI ws2_TransmitPackets(u64, const void*, u32, u32, win64_overlapped*, u32);
i32 TRT_GUEST_ABI ws2_WSARecvMsg(u64, void*, u32*, win64_overlapped*, void*);
i32 TRT_GUEST_ABI ws2_WSASendMsg(u64, const void*, u32, u32*, win64_overlapped*, void*);
i32 TRT_GUEST_ABI ws2_WSARecvEx(u64, char*, i32, i32*);

i32 TRT_GUEST_ABI ws2_WSAIoctl(u64 s, u32 dwIoControlCode,
                               void* lpvInBuffer, u32 cbInBuffer,
                               void* lpvOutBuffer, u32 cbOutBuffer,
                               u32* lpcbBytesReturned, void* ov, void* comp) {
  (void)lpvInBuffer; (void)cbInBuffer; (void)lpvOutBuffer; (void)cbOutBuffer;
  (void)ov; (void)comp;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (lpcbBytesReturned) *lpcbBytesReturned = 0;
  if (dwIoControlCode == k_win_fionbio && lpvInBuffer && cbInBuffer >= 4) {
    u32 val = 0;
    memcpy(&val, lpvInBuffer, 4);
    return ws2_ioctlsocket(s, (i32)k_win_fionbio, &val);
  }
  if (dwIoControlCode == k_win_fionread && lpvOutBuffer && cbOutBuffer >= 4) {
    u32 val = 0;
    i32 r = ws2_ioctlsocket(s, (i32)k_win_fionread, &val);
    if (r == 0) {
      memcpy(lpvOutBuffer, &val, 4);
      if (lpcbBytesReturned) *lpcbBytesReturned = 4;
    }
    return r;
  }
  if (dwIoControlCode == 0x98000004u /*SIO_KEEPALIVE_VALS*/) {
    set_wsa_err(0);
    return 0;
  }
  if (dwIoControlCode == 0xC8000006u /*SIO_GET_EXTENSION_FUNCTION_POINTER*/) {
    struct wsa_guid { u32 d1; u16 d2; u16 d3; u8 d4[8]; };
    static const wsa_guid g_connect_ex =
        {0x25a207b9u, 0xddf3u, 0x4660u, {0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}};
    static const wsa_guid g_accept_ex =
        {0xb5367df1u, 0xcbacu, 0x11cfu, {0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
    static const wsa_guid g_get_accept_ex_sa =
        {0xb5367df2u, 0xcbacu, 0x11cfu, {0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
    static const wsa_guid g_disconnect_ex =
        {0x7fda2e11u, 0x8630u, 0x436fu, {0xa0,0x31,0xf5,0x36,0xa6,0xee,0xc1,0x57}};
    static const wsa_guid g_transmit_file =
        {0xb5367df0u, 0xcbacu, 0x11cfu, {0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
    static const wsa_guid g_transmit_pkts =
        {0xd9689da0u, 0x1f90u, 0x11d3u, {0x99,0x71,0x00,0xc0,0x4f,0x68,0xc8,0x76}};
    static const wsa_guid g_wsa_recvmsg =
        {0xf689d7c8u, 0x6f1fu, 0x436bu, {0x8a,0x53,0xe5,0x4f,0xe3,0x51,0xc3,0x22}};
    static const wsa_guid g_wsa_sendmsg =
        {0xa441e712u, 0x754fu, 0x43cau, {0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}};
    static const wsa_guid g_wsa_poll =
        {0x18c76f85u, 0xdc66u, 0x4964u, {0x97,0x2e,0x23,0xc2,0x72,0x38,0x31,0x2b}};
    if (!lpvInBuffer || cbInBuffer < 16 || !lpvOutBuffer || cbOutBuffer < 8) {
      set_wsa_err(k_wsa_efault);
      return k_socket_error;
    }
    void* ext_fn = nullptr;
    if (memcmp(lpvInBuffer, &g_connect_ex, 16) == 0) ext_fn = (void*)&ws2_ConnectEx;
    else if (memcmp(lpvInBuffer, &g_accept_ex, 16) == 0) ext_fn = (void*)&ws2_AcceptEx;
    else if (memcmp(lpvInBuffer, &g_get_accept_ex_sa, 16) == 0) ext_fn = (void*)&ws2_GetAcceptExSockaddrs;
    else if (memcmp(lpvInBuffer, &g_disconnect_ex, 16) == 0) ext_fn = (void*)&ws2_DisconnectEx;
    else if (memcmp(lpvInBuffer, &g_transmit_file, 16) == 0) ext_fn = (void*)&ws2_TransmitFile;
    else if (memcmp(lpvInBuffer, &g_transmit_pkts, 16) == 0) ext_fn = (void*)&ws2_TransmitPackets;
    else if (memcmp(lpvInBuffer, &g_wsa_recvmsg, 16) == 0) ext_fn = (void*)&ws2_WSARecvMsg;
    else if (memcmp(lpvInBuffer, &g_wsa_sendmsg, 16) == 0) ext_fn = (void*)&ws2_WSASendMsg;
    else if (memcmp(lpvInBuffer, &g_wsa_poll, 16) == 0) ext_fn = (void*)&ws2_WSAPoll;
    if (ext_fn) {
      memcpy(lpvOutBuffer, &ext_fn, sizeof(ext_fn));
      if (lpcbBytesReturned) *lpcbBytesReturned = (u32)sizeof(ext_fn);
      set_wsa_err(0);
      return 0;
    }
  }
  char line[128];
  snprintf(line, sizeof(line), "ws2_32: WSAIoctl(0x%08x) -> WSAEOPNOTSUPP", dwIoControlCode);
  ws2_log(line);
  set_wsa_err(k_wsa_eopnotsupp);
  return k_socket_error;
}

// ---------- mswsock extension functions (POSIX offline host) ---------------
void msw_complete_ov(win64_overlapped* ov, u32 bytes) {
  if (!ov) return;
  ov->Internal = 0;
  ov->InternalHigh = (u64)bytes;
  if (ov->hEvent) {
    if (auto fn = (pfn_SetEvent)k32_fn("SetEvent")) fn(ov->hEvent);
  }
}

bool msw_send_all(int fd, const void* buf, u32 len) {
  const u8* p = (const u8*)buf;
  u32 sent_total = 0;
  while (sent_total < len) {
    ssize_t r = ::send(fd, p + sent_total, (size_t)(len - sent_total), MSG_NOSIGNAL);
    if (r < 0) {
      if (errno == EINTR) continue;
      set_wsa_err(errno_to_wsa(errno));
      return false;
    }
    if (r == 0) break;
    sent_total += (u32)r;
  }
  return sent_total == len;
}

bool msw_send_file_span(int fd, void* hFile, i64 offset, u32 req_bytes,
                        u32* out_sent) {
  typedef i32 (TRT_GUEST_ABI* pfn_ReadFile)(void*, void*, u32, u32*, void*);
  typedef i32 (TRT_GUEST_ABI* pfn_SetFilePointerEx)(void*, i64, i64*, u32);
  auto rf = (pfn_ReadFile)k32_fn("ReadFile");
  if (!rf) { set_wsa_err(k_wsa_eopnotsupp); return false; }
  if (offset >= 0) {
    if (auto sf = (pfn_SetFilePointerEx)k32_fn("SetFilePointerEx")) {
      sf(hFile, offset, nullptr, 0 /*FILE_BEGIN*/);
    }
  }
  u8 chunk[8192];
  u32 total = 0;
  const bool to_eof = (req_bytes == 0);
  while (to_eof || total < req_bytes) {
    u32 want = sizeof(chunk);
    if (!to_eof && (req_bytes - total) < want) want = req_bytes - total;
    u32 got = 0;
    if (!rf(hFile, chunk, want, &got, nullptr)) {
      set_wsa_err(k_wsa_einval);
      return false;
    }
    if (got == 0) break;
    if (!msw_send_all(fd, chunk, got)) return false;
    total += got;
  }
  if (out_sent) *out_sent += total;
  return true;
}

i32 TRT_GUEST_ABI ws2_ConnectEx(u64 s, const u8* name, i32 namelen,
                                void* lpSendBuffer, u32 dwSendDataLength,
                                u32* lpdwBytesSent,
                                win64_overlapped* lpOverlapped) {
  if (!lpOverlapped) { set_wsa_err(k_wsa_einval); return 0; }
  if (lpdwBytesSent) *lpdwBytesSent = 0;
  if (ws2_connect(s, name, namelen) != 0) return 0;
  u32 sent = 0;
  if (lpSendBuffer && dwSendDataLength > 0) {
    i32 r = ws2_send(s, (const char*)lpSendBuffer, (i32)dwSendDataLength, 0);
    if (r < 0) return 0;
    sent = (u32)r;
  }
  if (lpdwBytesSent) *lpdwBytesSent = sent;
  msw_complete_ov(lpOverlapped, sent);
  set_wsa_err(0);
  return 1;
}

i32 TRT_GUEST_ABI ws2_AcceptEx(u64 sListenSocket, u64 sAcceptSocket,
                               u8* lpOutputBuffer, u32 dwReceiveDataLength,
                               u32 dwLocalAddressLength,
                               u32 dwRemoteAddressLength,
                               u32* lpdwBytesReceived,
                               win64_overlapped* lpOverlapped) {
  int lfd = sock_to_fd(sListenSocket);
  int afd = sock_to_fd(sAcceptSocket);
  if (lfd < 0 || afd < 0) { set_wsa_err(k_wsa_enotsock); return 0; }
  if (!lpOutputBuffer || dwLocalAddressLength < 16 || dwRemoteAddressLength < 16) {
    set_wsa_err(k_wsa_einval);
    return 0;
  }
  if (lpdwBytesReceived) *lpdwBytesReceived = 0;
  struct sockaddr_storage remote_ss;
  socklen_t remote_len = sizeof(remote_ss);
  int cfd = ::accept(lfd, (struct sockaddr*)&remote_ss, &remote_len);
  if (cfd < 0) { set_wsa_err(errno_to_wsa(errno)); return 0; }
  if (::dup2(cfd, afd) < 0) {
    int e = errno;
    ::close(cfd);
    set_wsa_err(errno_to_wsa(e));
    return 0;
  }
  ::close(cfd);
  sock_meta_init(afd);
  memset(lpOutputBuffer + dwReceiveDataLength, 0,
         (size_t)(dwLocalAddressLength + dwRemoteAddressLength));
  struct sockaddr_storage local_ss;
  socklen_t local_len = sizeof(local_ss);
  if (::getsockname(afd, (struct sockaddr*)&local_ss, &local_len) == 0) {
    i32 lcap = (i32)dwLocalAddressLength;
    sockaddr_posix_to_win((const struct sockaddr*)&local_ss, local_len,
                          lpOutputBuffer + dwReceiveDataLength, &lcap);
  }
  i32 rcap = (i32)dwRemoteAddressLength;
  sockaddr_posix_to_win((const struct sockaddr*)&remote_ss, remote_len,
                        lpOutputBuffer + dwReceiveDataLength + dwLocalAddressLength,
                        &rcap);
  u32 recvd = 0;
  if (dwReceiveDataLength > 0) {
    ssize_t rr = ::recv(afd, lpOutputBuffer, (size_t)dwReceiveDataLength, 0);
    if (rr < 0) { set_wsa_err(errno_to_wsa(errno)); return 0; }
    recvd = (u32)rr;
  }
  if (lpdwBytesReceived) *lpdwBytesReceived = recvd;
  msw_complete_ov(lpOverlapped, recvd);
  set_wsa_err(0);
  return 1;
}

void TRT_GUEST_ABI ws2_GetAcceptExSockaddrs(
    u8* lpOutputBuffer, u32 dwReceiveDataLength, u32 dwLocalAddressLength,
    u32 dwRemoteAddressLength, u8** LocalSockaddr, i32* LocalSockaddrLength,
    u8** RemoteSockaddr, i32* RemoteSockaddrLength) {
  auto sa_len_for = [](const u8* sa, u32 cap) -> i32 {
    if (!sa || cap < 2) return 0;
    u16 fam = 0;
    memcpy(&fam, sa, 2);
    if (fam == (u16)k_win_af_inet) return 16;
    if (fam == (u16)k_win_af_inet6) return 28;
    return (cap >= 16) ? (i32)(cap - 16) : (i32)cap;
  };
  u8* loc = lpOutputBuffer ? (lpOutputBuffer + dwReceiveDataLength) : nullptr;
  u8* rem = lpOutputBuffer
                ? (lpOutputBuffer + dwReceiveDataLength + dwLocalAddressLength)
                : nullptr;
  if (LocalSockaddr) *LocalSockaddr = loc;
  if (LocalSockaddrLength) *LocalSockaddrLength = sa_len_for(loc, dwLocalAddressLength);
  if (RemoteSockaddr) *RemoteSockaddr = rem;
  if (RemoteSockaddrLength) *RemoteSockaddrLength = sa_len_for(rem, dwRemoteAddressLength);
}

i32 TRT_GUEST_ABI ws2_DisconnectEx(u64 s, win64_overlapped* lpOverlapped,
                                   u32 dwFlags, u32 dwReserved) {
  (void)dwFlags; (void)dwReserved;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return 0; }
  ::shutdown(fd, SHUT_RDWR);
  msw_complete_ov(lpOverlapped, 0);
  set_wsa_err(0);
  return 1;
}

i32 TRT_GUEST_ABI ws2_TransmitFile(u64 s, void* hFile, u32 nNumberOfBytesToWrite,
                                   u32 nNumberOfBytesPerSend,
                                   win64_overlapped* lpOverlapped,
                                   void* lpTransmitBuffers_v, u32 dwFlags) {
  (void)nNumberOfBytesPerSend;
  struct xmit_bufs { void* Head; u32 HeadLength; u32 _p0; void* Tail; u32 TailLength; u32 _p1; };
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return 0; }
  const xmit_bufs* tb = (const xmit_bufs*)lpTransmitBuffers_v;
  u32 total = 0;
  if (tb && tb->Head && tb->HeadLength > 0) {
    if (!msw_send_all(fd, tb->Head, tb->HeadLength)) return 0;
    total += tb->HeadLength;
  }
  if (hFile && hFile != (void*)(intptr_t)-1) {
    if (!msw_send_file_span(fd, hFile, -1, nNumberOfBytesToWrite, &total)) return 0;
  }
  if (tb && tb->Tail && tb->TailLength > 0) {
    if (!msw_send_all(fd, tb->Tail, tb->TailLength)) return 0;
    total += tb->TailLength;
  }
  if (dwFlags & 0x01u /*TF_DISCONNECT*/) ::shutdown(fd, SHUT_RDWR);
  msw_complete_ov(lpOverlapped, total);
  set_wsa_err(0);
  return 1;
}

i32 TRT_GUEST_ABI ws2_TransmitPackets(u64 s, const void* lpPacketArray_v,
                                      u32 nElementCount, u32 nSendSize,
                                      win64_overlapped* lpOverlapped, u32 dwFlags) {
  (void)nSendSize;
  struct tp_elem {
    u32 dwElFlags;
    u32 cLength;
    union {
      struct { i64 nFileOffset; void* hFile; };
      void* pBuffer;
    };
  };
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return 0; }
  const tp_elem* elems = (const tp_elem*)lpPacketArray_v;
  if (!elems && nElementCount > 0) { set_wsa_err(k_wsa_efault); return 0; }
  u32 total = 0;
  for (u32 i = 0; i < nElementCount; ++i) {
    if (elems[i].dwElFlags & 1u /*TP_ELEMENT_MEMORY*/) {
      if (elems[i].pBuffer && elems[i].cLength > 0) {
        if (!msw_send_all(fd, elems[i].pBuffer, elems[i].cLength)) return 0;
        total += elems[i].cLength;
      }
    } else if (elems[i].dwElFlags & 2u /*TP_ELEMENT_FILE*/) {
      if (elems[i].hFile && elems[i].hFile != (void*)(intptr_t)-1) {
        if (!msw_send_file_span(fd, elems[i].hFile, elems[i].nFileOffset,
                                elems[i].cLength, &total))
          return 0;
      }
    }
  }
  if (dwFlags & 0x01u /*TP_DISCONNECT*/) ::shutdown(fd, SHUT_RDWR);
  msw_complete_ov(lpOverlapped, total);
  set_wsa_err(0);
  return 1;
}

i32 TRT_GUEST_ABI ws2_WSARecvMsg(u64 s, void* msg_v, u32* recvd,
                                 win64_overlapped* ov, void* comp) {
  (void)comp;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  win64_wsamsg* wmsg = (win64_wsamsg*)msg_v;
  if (!wmsg || !wmsg->lpBuffers || wmsg->dwBufferCount == 0 || wmsg->dwBufferCount > 64) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  struct iovec iov[64];
  for (u32 i = 0; i < wmsg->dwBufferCount; ++i) {
    iov[i].iov_base = wmsg->lpBuffers[i].buf;
    iov[i].iov_len = wmsg->lpBuffers[i].len;
  }
  struct sockaddr_storage ss;
  struct msghdr pm;
  memset(&pm, 0, sizeof(pm));
  pm.msg_name = wmsg->name ? &ss : nullptr;
  pm.msg_namelen = wmsg->name ? sizeof(ss) : 0;
  pm.msg_iov = iov;
  pm.msg_iovlen = wmsg->dwBufferCount;
  ssize_t r = ::recvmsg(fd, &pm, (int)wmsg->dwFlags);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  if (wmsg->name && pm.msg_namelen > 0) {
    sockaddr_posix_to_win((const struct sockaddr*)&ss, pm.msg_namelen,
                          wmsg->name, &wmsg->namelen);
  }
  wmsg->Control.len = 0;
  wmsg->dwFlags = (u32)pm.msg_flags;
  if (recvd) *recvd = (u32)r;
  msw_complete_ov(ov, (u32)r);
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSASendMsg(u64 s, const void* msg_v, u32 flags, u32* sent,
                                 win64_overlapped* ov, void* comp) {
  (void)comp;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  const win64_wsamsg* wmsg = (const win64_wsamsg*)msg_v;
  if (!wmsg || !wmsg->lpBuffers || wmsg->dwBufferCount == 0 || wmsg->dwBufferCount > 64) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  struct iovec iov[64];
  for (u32 i = 0; i < wmsg->dwBufferCount; ++i) {
    iov[i].iov_base = wmsg->lpBuffers[i].buf;
    iov[i].iov_len = wmsg->lpBuffers[i].len;
  }
  struct sockaddr_storage ss;
  socklen_t slen = 0;
  if (wmsg->name && wmsg->namelen > 0) {
    if (!sockaddr_win_to_posix(wmsg->name, wmsg->namelen, &ss, &slen)) {
      set_wsa_err(k_wsa_einval);
      return k_socket_error;
    }
  }
  struct msghdr pm;
  memset(&pm, 0, sizeof(pm));
  pm.msg_name = slen ? &ss : nullptr;
  pm.msg_namelen = slen;
  pm.msg_iov = iov;
  pm.msg_iovlen = wmsg->dwBufferCount;
  ssize_t r = ::sendmsg(fd, &pm, (int)flags | MSG_NOSIGNAL);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  if (sent) *sent = (u32)r;
  msw_complete_ov(ov, (u32)r);
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSARecvEx(u64 s, char* buf, i32 len, i32* flags) {
  i32 f = flags ? *flags : 0;
  i32 r = ws2_recv(s, buf, len, f);
  if (r >= 0 && flags) *flags = 0;
  return r;
}

void* TRT_GUEST_ABI ws2_WSAAsyncGetHostByName(void* hWnd, u32 wMsg,
                                              const char* name, char* buf,
                                              i32 buflen) {
  (void)hWnd; (void)wMsg; (void)name; (void)buf; (void)buflen;
  ws2_log("ws2_32: WSAAsyncGetHostByName -> 0 (WSAEOPNOTSUPP)");
  set_wsa_err(k_wsa_eopnotsupp);
  return nullptr;
}

i32 TRT_GUEST_ABI ws2_WSACancelAsyncRequest(void* hTask) {
  (void)hTask;
  set_wsa_err(k_wsa_einval);
  return k_socket_error;
}

#else  // _WIN32 (UWP console host)

i32 TRT_GUEST_ABI ws2_WSAStartup(u16 ver, LPWSADATA data) {
  return ::WSAStartup(ver, data);
}
i32 TRT_GUEST_ABI ws2_WSACleanup(void) { return ::WSACleanup(); }
i32 TRT_GUEST_ABI ws2_WSAGetLastError(void) { return ::WSAGetLastError(); }
void TRT_GUEST_ABI ws2_WSASetLastError(i32 e) { ::WSASetLastError(e); }
u64 TRT_GUEST_ABI ws2_socket(i32 af, i32 type, i32 p) {
  return (u64)::socket(af, type, p);
}
i32 TRT_GUEST_ABI ws2_closesocket(u64 s) { return ::closesocket((SOCKET)s); }
i32 TRT_GUEST_ABI ws2_bind(u64 s, const struct sockaddr* n, i32 l) {
  return ::bind((SOCKET)s, n, l);
}
i32 TRT_GUEST_ABI ws2_connect(u64 s, const struct sockaddr* n, i32 l) {
  return ::connect((SOCKET)s, n, l);
}
i32 TRT_GUEST_ABI ws2_listen(u64 s, i32 b) { return ::listen((SOCKET)s, b); }
u64 TRT_GUEST_ABI ws2_accept(u64 s, struct sockaddr* a, i32* l) {
  return (u64)::accept((SOCKET)s, a, l);
}
i32 TRT_GUEST_ABI ws2_shutdown(u64 s, i32 h) { return ::shutdown((SOCKET)s, h); }
i32 TRT_GUEST_ABI ws2_send(u64 s, const char* b, i32 l, i32 f) {
  return ::send((SOCKET)s, b, l, f);
}
i32 TRT_GUEST_ABI ws2_recv(u64 s, char* b, i32 l, i32 f) {
  return ::recv((SOCKET)s, b, l, f);
}
i32 TRT_GUEST_ABI ws2_sendto(u64 s, const char* b, i32 l, i32 f,
                             const struct sockaddr* to, i32 tolen) {
  return ::sendto((SOCKET)s, b, l, f, to, tolen);
}
i32 TRT_GUEST_ABI ws2_recvfrom(u64 s, char* b, i32 l, i32 f,
                               struct sockaddr* fr, i32* frlen) {
  return ::recvfrom((SOCKET)s, b, l, f, fr, frlen);
}
i32 TRT_GUEST_ABI ws2_getsockname(u64 s, struct sockaddr* n, i32* l) {
  return ::getsockname((SOCKET)s, n, l);
}
i32 TRT_GUEST_ABI ws2_getpeername(u64 s, struct sockaddr* n, i32* l) {
  return ::getpeername((SOCKET)s, n, l);
}
i32 TRT_GUEST_ABI ws2_setsockopt(u64 s, i32 lv, i32 on, const char* ov, i32 ol) {
  return ::setsockopt((SOCKET)s, lv, on, ov, ol);
}
i32 TRT_GUEST_ABI ws2_getsockopt(u64 s, i32 lv, i32 on, char* ov, i32* ol) {
  return ::getsockopt((SOCKET)s, lv, on, ov, ol);
}
i32 TRT_GUEST_ABI ws2_ioctlsocket(u64 s, i32 cmd, u_long* argp) {
  return ::ioctlsocket((SOCKET)s, cmd, argp);
}
i32 TRT_GUEST_ABI ws2_select(i32 nfds, fd_set* r, fd_set* w, fd_set* e,
                             struct timeval* t) {
  return ::select(nfds, r, w, e, t);
}
i32 TRT_GUEST_ABI ws2___WSAFDIsSet(u64 fd, fd_set* set) {
  return ::__WSAFDIsSet((SOCKET)fd, set);
}
u32 TRT_GUEST_ABI ws2_htonl(u32 v) { return ::htonl(v); }
u16 TRT_GUEST_ABI ws2_htons(u16 v) { return ::htons(v); }
u32 TRT_GUEST_ABI ws2_ntohl(u32 v) { return ::ntohl(v); }
u16 TRT_GUEST_ABI ws2_ntohs(u16 v) { return ::ntohs(v); }
u32 TRT_GUEST_ABI ws2_inet_addr(const char* cp) { return (u32)::inet_addr(cp); }

void* msw_w32_ext(u64 s_hint, const void* guid) {
  SOCKET s = (s_hint && s_hint != ~(u64)0) ? (SOCKET)s_hint : INVALID_SOCKET;
  SOCKET tmp = INVALID_SOCKET;
  if (s == INVALID_SOCKET) {
    tmp = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    s = tmp;
  }
  void* fn = nullptr;
  DWORD cb = 0;
  if (s != INVALID_SOCKET) {
    ::WSAIoctl(s, 0xC8000006u /*SIO_GET_EXTENSION_FUNCTION_POINTER*/,
               const_cast<void*>(guid), 16, &fn, (DWORD)sizeof(fn), &cb,
               nullptr, nullptr);
  }
  if (tmp != INVALID_SOCKET) ::closesocket(tmp);
  return fn;
}

i32 TRT_GUEST_ABI ws2_ConnectEx(u64 s, const u8* name, i32 namelen,
                                void* send_buf, u32 send_len, u32* sent,
                                void* ov) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0x25a207b9u, 0xddf3u, 0x4660u, {0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e}};
  typedef i32 (WINAPI* pfn)(SOCKET, const struct sockaddr*, int, PVOID, DWORD, LPDWORD, LPOVERLAPPED);
  if (auto f = (pfn)msw_w32_ext(s, &g))
    return f((SOCKET)s, (const struct sockaddr*)name, (int)namelen, send_buf,
             (DWORD)send_len, (LPDWORD)sent, (LPOVERLAPPED)ov);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return 0;
}

i32 TRT_GUEST_ABI ws2_AcceptEx(u64 sListen, u64 sAccept, u8* buf, u32 recv_len,
                               u32 local_len, u32 remote_len, u32* recvd,
                               void* ov) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0xb5367df1u, 0xcbacu, 0x11cfu, {0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
  typedef i32 (WINAPI* pfn)(SOCKET, SOCKET, PVOID, DWORD, DWORD, DWORD, LPDWORD, LPOVERLAPPED);
  if (auto f = (pfn)msw_w32_ext(sListen, &g))
    return f((SOCKET)sListen, (SOCKET)sAccept, buf, (DWORD)recv_len,
             (DWORD)local_len, (DWORD)remote_len, (LPDWORD)recvd, (LPOVERLAPPED)ov);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return 0;
}

void TRT_GUEST_ABI ws2_GetAcceptExSockaddrs(
    u8* buf, u32 recv_len, u32 local_len, u32 remote_len,
    u8** local_sa, i32* local_sa_len, u8** remote_sa, i32* remote_sa_len) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0xb5367df2u, 0xcbacu, 0x11cfu, {0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
  typedef void (WINAPI* pfn)(PVOID, DWORD, DWORD, DWORD, struct sockaddr**, LPINT, struct sockaddr**, LPINT);
  if (auto f = (pfn)msw_w32_ext(~(u64)0, &g)) {
    f(buf, (DWORD)recv_len, (DWORD)local_len, (DWORD)remote_len,
      (struct sockaddr**)local_sa, (LPINT)local_sa_len,
      (struct sockaddr**)remote_sa, (LPINT)remote_sa_len);
    return;
  }
  if (local_sa) *local_sa = buf ? buf + recv_len : nullptr;
  if (local_sa_len) *local_sa_len = (i32)local_len;
  if (remote_sa) *remote_sa = buf ? buf + recv_len + local_len : nullptr;
  if (remote_sa_len) *remote_sa_len = (i32)remote_len;
}

i32 TRT_GUEST_ABI ws2_DisconnectEx(u64 s, void* ov, u32 flags, u32 res) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0x7fda2e11u, 0x8630u, 0x436fu, {0xa0,0x31,0xf5,0x36,0xa6,0xee,0xc1,0x57}};
  typedef i32 (WINAPI* pfn)(SOCKET, LPOVERLAPPED, DWORD, DWORD);
  if (auto f = (pfn)msw_w32_ext(s, &g))
    return f((SOCKET)s, (LPOVERLAPPED)ov, (DWORD)flags, (DWORD)res);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return 0;
}

i32 TRT_GUEST_ABI ws2_TransmitFile(u64 s, void* hFile, u32 bytes, u32 chunk,
                                   void* ov, void* tb, u32 flags) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0xb5367df0u, 0xcbacu, 0x11cfu, {0x95,0xca,0x00,0x80,0x5f,0x48,0xa1,0x92}};
  typedef i32 (WINAPI* pfn)(SOCKET, HANDLE, DWORD, DWORD, LPOVERLAPPED, void*, DWORD);
  if (auto f = (pfn)msw_w32_ext(s, &g))
    return f((SOCKET)s, (HANDLE)hFile, (DWORD)bytes, (DWORD)chunk, (LPOVERLAPPED)ov, tb, (DWORD)flags);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return 0;
}

i32 TRT_GUEST_ABI ws2_TransmitPackets(u64 s, const void* pkts, u32 count,
                                      u32 send_sz, void* ov, u32 flags) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0xd9689da0u, 0x1f90u, 0x11d3u, {0x99,0x71,0x00,0xc0,0x4f,0x68,0xc8,0x76}};
  typedef i32 (WINAPI* pfn)(SOCKET, const void*, DWORD, DWORD, LPOVERLAPPED, DWORD);
  if (auto f = (pfn)msw_w32_ext(s, &g))
    return f((SOCKET)s, pkts, (DWORD)count, (DWORD)send_sz, (LPOVERLAPPED)ov, (DWORD)flags);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSARecvMsg(u64 s, void* msg, u32* recvd, void* ov,
                                 void* comp) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0xf689d7c8u, 0x6f1fu, 0x436bu, {0x8a,0x53,0xe5,0x4f,0xe3,0x51,0xc3,0x22}};
  typedef i32 (WINAPI* pfn)(SOCKET, void*, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
  if (auto f = (pfn)msw_w32_ext(s, &g))
    return f((SOCKET)s, msg, (LPDWORD)recvd, (LPWSAOVERLAPPED)ov, (LPWSAOVERLAPPED_COMPLETION_ROUTINE)comp);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}

i32 TRT_GUEST_ABI ws2_WSASendMsg(u64 s, const void* msg, u32 flags, u32* sent,
                                 void* ov, void* comp) {
  static const struct { u32 d1; u16 d2; u16 d3; u8 d4[8]; } g =
      {0xa441e712u, 0x754f, 0x43cau, {0x84,0xa7,0x0d,0xee,0x44,0xcf,0x60,0x6d}};
  typedef i32 (WINAPI* pfn)(SOCKET, const void*, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
  if (auto f = (pfn)msw_w32_ext(s, &g))
    return f((SOCKET)s, msg, (DWORD)flags, (LPDWORD)sent, (LPWSAOVERLAPPED)ov, (LPWSAOVERLAPPED_COMPLETION_ROUTINE)comp);
  ::WSASetLastError(WSAEOPNOTSUPP);
  return SOCKET_ERROR;
}

i32 TRT_GUEST_ABI ws2_WSARecvEx(u64 s, char* buf, i32 len, i32* flags) {
  i32 f = flags ? *flags : 0;
  int r = ::recv((SOCKET)s, buf, (int)len, (int)f);
  if (r >= 0 && flags) *flags = 0;
  return (i32)r;
}

#endif  // !_WIN32

// ---------- registration tables -------------------------------------------
const trt_named_fn k_mswsock_fns[] = {
    {"AcceptEx",             (void*)&ws2_AcceptEx},
    {"ConnectEx",            (void*)&ws2_ConnectEx},
    {"DisconnectEx",         (void*)&ws2_DisconnectEx},
    {"GetAcceptExSockaddrs", (void*)&ws2_GetAcceptExSockaddrs},
    {"TransmitFile",         (void*)&ws2_TransmitFile},
    {"TransmitPackets",      (void*)&ws2_TransmitPackets},
    {"WSARecvMsg",           (void*)&ws2_WSARecvMsg},
    {"WSASendMsg",           (void*)&ws2_WSASendMsg},
    {"WSARecvEx",            (void*)&ws2_WSARecvEx},
};
#if !defined(_WIN32)
void* TRT_GUEST_ABI ws2_getservbyname(const char* name, const char* proto);
void* TRT_GUEST_ABI ws2_getservbyport(i32 port, const char* proto);
#endif

const trt_named_fn k_wsock32_fns[] = {
    {"accept",         (void*)&ws2_accept},
    {"bind",           (void*)&ws2_bind},
    {"closesocket",    (void*)&ws2_closesocket},
    {"connect",        (void*)&ws2_connect},
    {"getpeername",    (void*)&ws2_getpeername},
    {"getsockname",    (void*)&ws2_getsockname},
    {"getsockopt",     (void*)&ws2_getsockopt},
    {"htonl",          (void*)&ws2_htonl},
    {"htons",          (void*)&ws2_htons},
    {"ioctlsocket",    (void*)&ws2_ioctlsocket},
    {"inet_addr",      (void*)&ws2_inet_addr},
    {"listen",         (void*)&ws2_listen},
    {"ntohl",          (void*)&ws2_ntohl},
    {"ntohs",          (void*)&ws2_ntohs},
    {"recv",           (void*)&ws2_recv},
    {"recvfrom",       (void*)&ws2_recvfrom},
    {"select",         (void*)&ws2_select},
    {"send",           (void*)&ws2_send},
    {"sendto",         (void*)&ws2_sendto},
    {"setsockopt",     (void*)&ws2_setsockopt},
    {"shutdown",       (void*)&ws2_shutdown},
    {"socket",         (void*)&ws2_socket},
    {"WSAGetLastError",(void*)&ws2_WSAGetLastError},
    {"WSASetLastError",(void*)&ws2_WSASetLastError},
    {"WSAStartup",     (void*)&ws2_WSAStartup},
    {"WSACleanup",     (void*)&ws2_WSACleanup},
    {"__WSAFDIsSet",   (void*)&ws2___WSAFDIsSet},
    // WinSock ordinals shared by wsock32 / ws2_32
    {"#1",   (void*)&ws2_accept},
    {"#2",   (void*)&ws2_bind},
    {"#3",   (void*)&ws2_closesocket},
    {"#4",   (void*)&ws2_connect},
    {"#5",   (void*)&ws2_getpeername},
    {"#6",   (void*)&ws2_getsockname},
    {"#7",   (void*)&ws2_getsockopt},
    {"#8",   (void*)&ws2_htonl},
    {"#9",   (void*)&ws2_htons},
    {"#10",  (void*)&ws2_ioctlsocket},
    {"#11",  (void*)&ws2_inet_addr},
    {"#13",  (void*)&ws2_listen},
    {"#14",  (void*)&ws2_ntohl},
    {"#15",  (void*)&ws2_ntohs},
    {"#16",  (void*)&ws2_recv},
    {"#17",  (void*)&ws2_recvfrom},
    {"#18",  (void*)&ws2_select},
    {"#19",  (void*)&ws2_send},
    {"#20",  (void*)&ws2_sendto},
    {"#21",  (void*)&ws2_setsockopt},
    {"#22",  (void*)&ws2_shutdown},
    {"#23",  (void*)&ws2_socket},
    {"#111", (void*)&ws2_WSAGetLastError},
    {"#112", (void*)&ws2_WSASetLastError},
    {"#115", (void*)&ws2_WSAStartup},
    {"#116", (void*)&ws2_WSACleanup},
    {"#151", (void*)&ws2___WSAFDIsSet},
#if !defined(_WIN32)
    {"inet_ntoa",      (void*)&ws2_inet_ntoa},
    {"gethostbyaddr",  (void*)&ws2_gethostbyaddr},
    {"gethostbyname",  (void*)&ws2_gethostbyname},
    {"getprotobyname", (void*)&ws2_getprotobyname},
    {"getservbyname",  (void*)&ws2_getservbyname},
    {"getservbyport",  (void*)&ws2_getservbyport},
    {"gethostname",    (void*)&ws2_gethostname},
    {"WSAAsyncGetHostByName", (void*)&ws2_WSAAsyncGetHostByName},
    {"WSACancelAsyncRequest", (void*)&ws2_WSACancelAsyncRequest},
    {"#12",  (void*)&ws2_inet_ntoa},
    {"#51",  (void*)&ws2_gethostbyaddr},
    {"#52",  (void*)&ws2_gethostbyname},
    {"#53",  (void*)&ws2_getprotobyname},
    {"#55",  (void*)&ws2_getservbyname},
    {"#56",  (void*)&ws2_getservbyport},
    {"#57",  (void*)&ws2_gethostname},
    {"#103", (void*)&ws2_WSAAsyncGetHostByName},
    {"#108", (void*)&ws2_WSACancelAsyncRequest},
#endif
};

#if !defined(_WIN32)
// forward decls: the extra-fns table sits above the definitions
void* TRT_GUEST_ABI ws2_getservbyname(const char* name, const char* proto);
void* TRT_GUEST_ABI ws2_getservbyport(i32 port, const char* proto);
i32 TRT_GUEST_ABI ws2_WSADuplicateSocketA(u64 s, u32 dwProcessId,
                                          void* lpProtocolInfo);
int TRT_GUEST_ABI ws2_WSAGetOverlappedResult(u64 s, void* lpOverlapped,
                                             u32* lpcbTransfer, int fWait,
                                             u32* lpdwFlags);
i32 TRT_GUEST_ABI ws2_WSAStringToAddressA(const char* AddressString,
                                          i32 AddressFamily,
                                          const void* lpProtocolInfo,
                                          u8* lpAddress, i32* lpAddressLength);

// ---- BotW-Native chain gaps (libcrypto-3 + SDL3 imports) ----

// getservbyname/getservbyport: no /etc/services database is shipped with the
// runtime. NULL = "service unknown" (real semantics); callers fall back to
// literal port numbers, which is all OpenSSL ever needs.
void* TRT_GUEST_ABI ws2_getservbyname(const char* name,
                                               const char* proto) {
  (void)proto;
  set_wsa_err(k_wsa_host_not_found);  // WSANO_DATA: name has no record
  return nullptr;
}

void* TRT_GUEST_ABI ws2_getservbyport(i32 port, const char* proto) {
  (void)port;
  (void)proto;
  set_wsa_err(k_wsa_host_not_found);
  return nullptr;
}

// WSADuplicateSocketA: cross-process socket duplication has no consumer on
// the console (one process, no WSAPROTOCOL negotiation). Named failure.
i32 TRT_GUEST_ABI ws2_WSADuplicateSocketA(u64 s, u32 dwProcessId,
                                          void* lpProtocolInfo) {
  (void)s;
  (void)dwProcessId;
  (void)lpProtocolInfo;
  set_wsa_err(k_wsa_einval);
  return k_wsa_einval;
}

// WSAGetOverlappedResult: the bridge's async I/O completes synchronously, so
// there are no deferred results to fetch. FALSE + WSAEINVAL (no overlapped
// operation pending) is the honest answer.
int TRT_GUEST_ABI ws2_WSAGetOverlappedResult(u64 s, void* lpOverlapped,
                                             u32* lpcbTransfer, int fWait,
                                             u32* lpdwFlags) {
  (void)s;
  (void)lpOverlapped;
  (void)fWait;
  if (lpcbTransfer) *lpcbTransfer = 0;
  if (lpdwFlags) *lpdwFlags = 0;
  set_wsa_err(k_wsa_einval);
  return 0;  // FALSE
}

// WSAStringToAddressA: honest parse — dotted-quad IPv4 via inet_pton into the
// guest sockaddr_in (family 2, port 0, network-order address); anything else
// (IPv6 text, hostnames) fails WSAEINVAL like real Win32 without the parser.
i32 TRT_GUEST_ABI ws2_WSAStringToAddressA(const char* AddressString,
                                          i32 AddressFamily,
                                          const void* lpProtocolInfo,
                                          u8* lpAddress, i32* lpAddressLength) {
  (void)lpProtocolInfo;
  if (!AddressString || !lpAddress || !lpAddressLength ||
      *lpAddressLength < 16) {
    set_wsa_err(k_wsa_einval);
    return k_wsa_einval;
  }
  if (AddressFamily != 2 /* AF_INET */) {
    set_wsa_err(k_wsa_eafnosupport);
    return k_wsa_eafnosupport;
  }
  unsigned char bin[4];
  if (::inet_pton(AF_INET, AddressString, bin) != 1) {
    set_wsa_err(k_wsa_einval);
    return k_wsa_einval;
  }
  memset(lpAddress, 0, 16);
  u16 fam = 2;
  memcpy(lpAddress, &fam, 2);          // sin_family
  // sin_port stays 0; sin_addr at offset 4, network order
  memcpy(lpAddress + 4, bin, 4);
  *lpAddressLength = 16;
  set_wsa_err(0);
  return 0;
}

i32 TRT_GUEST_ABI ws2_WSARecvFrom(u64 s, const win64_wsabuf* bufs, u32 count,
                                  u32* recvd, u32* flags, u8* from,
                                  i32* fromlen, void* ov, void* comp) {
  (void)ov; (void)comp;
  int fd = sock_to_fd(s);
  if (fd < 0) { set_wsa_err(k_wsa_enotsock); return k_socket_error; }
  if (!bufs || count == 0 || count > 1024) {
    set_wsa_err(k_wsa_einval);
    return k_socket_error;
  }
  struct iovec iov[64];
  const u32 n = count < 64 ? count : 64;
  for (u32 i = 0; i < n; ++i) {
    iov[i].iov_base = bufs[i].buf;
    iov[i].iov_len = bufs[i].len;
  }
  struct sockaddr_storage ss;
  memset(&ss, 0, sizeof(ss));
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &ss;
  msg.msg_namelen = sizeof(ss);
  msg.msg_iov = iov;
  msg.msg_iovlen = n;
  int iflags = flags ? (int)*flags : 0;
  ssize_t r = ::recvmsg(fd, &msg, iflags);
  if (r < 0) { set_wsa_err(errno_to_wsa(errno)); return k_socket_error; }
  if (from && fromlen && msg.msg_namelen > 0) {
    sockaddr_posix_to_win((const struct sockaddr*)&ss, msg.msg_namelen, from,
                          fromlen);
  }
  if (recvd) *recvd = (u32)r;
  if (flags) *flags = (u32)msg.msg_flags;
  set_wsa_err(0);
  return 0;
}

const trt_named_fn k_ws2_extra_fns[] = {
    {"WSASocketA",               (void*)&ws2_WSASocketA},
    {"WSASocketW",               (void*)&ws2_WSASocketW},
    {"WSAConnect",               (void*)&ws2_WSAConnect},
    {"WSASend",                  (void*)&ws2_WSASend},
    {"WSARecv",                  (void*)&ws2_WSARecv},
    {"WSARecvFrom",              (void*)&ws2_WSARecvFrom},
    {"WSASendDisconnect",        (void*)&ws2_WSASendDisconnect},
    {"WSAPoll",                  (void*)&ws2_WSAPoll},
    {"WSAIoctl",                 (void*)&ws2_WSAIoctl},
    {"WSAHtonl",                 (void*)&ws2_WSAHtonl},
    {"WSAHtons",                 (void*)&ws2_WSAHtons},
    {"WSANtohl",                 (void*)&ws2_WSANtohl},
    {"WSANtohs",                 (void*)&ws2_WSANtohs},
    {"WSACreateEvent",           (void*)&ws2_WSACreateEvent},
    {"WSACloseEvent",            (void*)&ws2_WSACloseEvent},
    {"WSASetEvent",              (void*)&ws2_WSASetEvent},
    {"WSAResetEvent",            (void*)&ws2_WSAResetEvent},
    {"WSAEventSelect",           (void*)&ws2_WSAEventSelect},
    {"WSAEnumNetworkEvents",     (void*)&ws2_WSAEnumNetworkEvents},
    {"WSAWaitForMultipleEvents", (void*)&ws2_WSAWaitForMultipleEvents},
    {"getaddrinfo",              (void*)&ws2_getaddrinfo},
    {"freeaddrinfo",             (void*)&ws2_freeaddrinfo},
    {"GetAddrInfoW",             (void*)&ws2_GetAddrInfoW},
    {"FreeAddrInfoW",            (void*)&ws2_FreeAddrInfoW},
    {"GetAddrInfoExW",           (void*)&ws2_GetAddrInfoExW},
    {"FreeAddrInfoExW",          (void*)&ws2_FreeAddrInfoExW},
    {"GetAddrInfoExCancel",      (void*)&ws2_GetAddrInfoExCancel},
    {"getnameinfo",              (void*)&ws2_getnameinfo},
    {"GetNameInfoW",             (void*)&ws2_GetNameInfoW},
    {"inet_pton",                (void*)&ws2_inet_pton},
    {"inet_ntop",                (void*)&ws2_inet_ntop},
    {"InetPtonW",                (void*)&ws2_InetPtonW},
    {"InetNtopW",                (void*)&ws2_InetNtopW},
    {"getservbyname",            (void*)&ws2_getservbyname},
    {"getservbyport",            (void*)&ws2_getservbyport},
    {"WSADuplicateSocketA",      (void*)&ws2_WSADuplicateSocketA},
    {"WSAGetOverlappedResult",   (void*)&ws2_WSAGetOverlappedResult},
    {"WSAStringToAddressA",      (void*)&ws2_WSAStringToAddressA},
};
#endif

}  // namespace

extern "C" int trt_bridge_register_ws2(void) {
  trt_module_register("wsock32.dll", TRT_ROUTE_BUILTIN, k_wsock32_fns,
                      (int)(sizeof(k_wsock32_fns) / sizeof(k_wsock32_fns[0])));
  trt_module_register("mswsock.dll", TRT_ROUTE_BUILTIN, k_mswsock_fns,
                      (int)(sizeof(k_mswsock_fns) / sizeof(k_mswsock_fns[0])));
  return 0;
}

extern "C" void* trt_ws2_resolve(const char* symbol) {
#if !defined(_WIN32)
  if (!symbol) return nullptr;
  const int n1 = (int)(sizeof(k_wsock32_fns) / sizeof(k_wsock32_fns[0]));
  for (int i = 0; i < n1; ++i)
    if (strcmp(k_wsock32_fns[i].name, symbol) == 0) return k_wsock32_fns[i].fn;
  const int n2 = (int)(sizeof(k_ws2_extra_fns) / sizeof(k_ws2_extra_fns[0]));
  for (int i = 0; i < n2; ++i)
    if (strcmp(k_ws2_extra_fns[i].name, symbol) == 0) return k_ws2_extra_fns[i].fn;
#else
  (void)symbol;
#endif
  return nullptr;
}
