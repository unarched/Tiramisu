// tiramisu/src/trt/bridge_shell.cpp
// Shell32 bridge. See bridge_shell.h.
//
// Folder mapping (guest C:\ is LocalState\drive_c):
//   CSIDL_PROFILE            -> C:\users\player
//   CSIDL_MYDOCUMENTS        -> C:\users\player\Documents
//   CSIDL_LOCAL_APPDATA      -> C:\users\player\AppData\Local
//   CSIDL_ROAMING_APPDATA    -> C:\users\player\AppData\Roaming
//   CSIDL_COMMON_APPDATA     -> C:\ProgramData
//   CSIDL_PERSONAL == MYDOCUMENTS; the rest fail visibly with the csidl in
//   the log (a game that needs CSIDL_PROGRAM_FILES is telling us something).
//
// SHGetKnownFolderPath maps the FOLDERID_* GUIDs games actually pass
// (Documents {FDD39AD0..}, LocalAppData {F1B32785..}, Profile {5E6C858F..},
// Roaming AppData {3EB685DB..}, ProgramData {62AB5D82..}).
//
// Both wide and ANSI entry points fill a MAX_PATH (260) buffer; the VFS
// mkdirs the folder when the SHF_FLAG_CREATE bit (0x8000) is set.
#include "bridge_shell.h"
#include "bridge_user32.h"
#include "pe.h"
#include "thunk.h"
#include "trt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
#ifdef _WIN32
#include <direct.h>  // _mkdir
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#endif

namespace shellhelpers {
inline int mk_dir(const char* p) {
#ifdef _WIN32
  return _mkdir(p);
#else
  return mkdir(p, 0755);
#endif
}
}

extern "C" {
// defined in vfs.cpp (C linkage)
int trt_vfs_resolve_utf16(const u16* guest_path, char* out, size_t out_cap);
}

// unique name, file scope, OUTSIDE extern "C" (the log collision rule)
namespace shelllog {
static void line(const char* s) { trt_core_log(s); }
}
#define log_line(s_) shelllog::line(s_)

namespace {

constexpr int S_OK_ = 0;
constexpr int E_FAIL_ = (int)0x80004005;
constexpr int E_INVALIDARG_ = (int)0x80070057;
constexpr int E_HANDLE_ = (int)0x80070006;
constexpr u32 k_max_path = 260;
constexpr u32 CSIDL_FLAG_CREATE = 0x8000;

// csidl -> vfs path (utf8). Returns 0 = known, 1 = unsupported (named).
int csidl_path(u32 csidl, char* out, u32 cap) {
  u32 base = csidl & ~CSIDL_FLAG_CREATE;
  switch (base) {
    case 0x0028:  // CSIDL_PROFILE
      snprintf(out, cap, "C:\\users\\player");
      break;
    case 0x0005:  // CSIDL_PERSONAL / CSIDL_MYDOCUMENTS
      snprintf(out, cap, "C:\\users\\player\\Documents");
      break;
    case 0x001C:  // CSIDL_LOCAL_APPDATA
      snprintf(out, cap, "C:\\users\\player\\AppData\\Local");
      break;
    case 0x001A:  // CSIDL_ROAMING_APPDATA
      snprintf(out, cap, "C:\\users\\player\\AppData\\Roaming");
      break;
    case 0x0023:  // CSIDL_COMMON_APPDATA
      snprintf(out, cap, "C:\\ProgramData");
      break;
    case 0x0026:  // CSIDL_LOCAL_APPDATA low integrity is the same dir here
      snprintf(out, cap, "C:\\users\\player\\AppData\\Local\\Low");
      break;
    case 0x0020:  // CSIDL_DESKTOPDIRECTORY
      snprintf(out, cap, "C:\\users\\player\\Desktop");
      break;
    case 0x0027:  // CSIDL_MYPICTURES
      snprintf(out, cap, "C:\\users\\player\\Pictures");
      break;
    default:
      return 1;
  }
  return 0;
}

// mkdir through the VFS so the game can write its save immediately
void ensure_dir(const char* vfs_path) {
  // resolve through the VFS to the host path, mkdir each component
  u16 wide[k_max_path];
  u32 n = 0;
  for (; vfs_path[n] && n < k_max_path - 1; ++n)
    wide[n] = (u16)(u8)vfs_path[n];
  wide[n] = 0;
  char host[1024];
  if (trt_vfs_resolve_utf16(wide, host, sizeof(host)) != 0) return;
  for (char* p = host + 1; *p; ++p) {
    if (*p == '/') {
      *p = 0;
      shellhelpers::mk_dir(host);  // EEXIST is fine
      *p = '/';
    }
  }
  shellhelpers::mk_dir(host);
}

void utf8_to_utf16(const char* in, u16* out, u32 cap) {
  u32 o = 0;
  for (u32 i = 0; in[i] && o + 1 < cap; ++i) out[o++] = (u16)(u8)in[i];
  out[o] = 0;
}

int TRT_GUEST_ABI shell_SHGetFolderPathW(void* hwnd, u32 csidl, void* token,
                                         u32 flags, u16* path_out) {
  (void)hwnd; (void)token;
  if (!path_out) return E_INVALIDARG_;
  char p8[k_max_path];
  if (csidl_path(csidl, p8, sizeof(p8)) != 0) {
    char line[128];
    snprintf(line, sizeof(line),
             "shell: SHGetFolderPathW csidl=0x%x -> E_FAIL (no mapping)", csidl);
    log_line(line);
    return E_FAIL_;
  }
  if (flags & CSIDL_FLAG_CREATE) ensure_dir(p8);
  utf8_to_utf16(p8, path_out, k_max_path);
  char line[160];
  snprintf(line, sizeof(line), "shell: SHGetFolderPathW csidl=0x%x -> %s%s",
           csidl, p8, (flags & CSIDL_FLAG_CREATE) ? " (created)" : "");
  log_line(line);
  return S_OK_;
}

int TRT_GUEST_ABI shell_SHGetFolderPathA(void* hwnd, u32 csidl, void* token,
                                         u32 flags, char* path_out) {
  if (!path_out) return E_INVALIDARG_;
  if (csidl_path(csidl, path_out, k_max_path) != 0) {
    char line[128];
    snprintf(line, sizeof(line),
             "shell: SHGetFolderPathA csidl=0x%x -> E_FAIL (no mapping)", csidl);
    log_line(line);
    return E_FAIL_;
  }
  if (flags & CSIDL_FLAG_CREATE) ensure_dir(path_out);
  char line[160];
  snprintf(line, sizeof(line), "shell: SHGetFolderPathA csidl=0x%x -> %s",
           csidl, path_out);
  log_line(line);
  return S_OK_;
}

// ---- FOLDERID GUIDs (first 8 bytes identify; games use these five) ----
struct guid8 { u32 a; u16 b, c; };
int knownfolder_path(const u8* g, char* out, u32 cap) {
  const guid8* id = (const guid8*)g;
  struct { u32 a; u16 b, c; const char* path; } table[] = {
      // FOLDERID_Documents {FDD39AD0-238F-46AF-ADB4-6C85480369C7}
      {0xFDD39AD0u, 0x238F, 0x46AF, "C:\\users\\player\\Documents"},
      // FOLDERID_LocalAppData {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
      {0xF1B32785u, 0x6FBA, 0x4FCF, "C:\\users\\player\\AppData\\Local"},
      // FOLDERID_Profile {5E6C858F-0E22-4760-9AFE-EA3317B67173}
      {0x5E6C858Fu, 0x0E22, 0x4760, "C:\\users\\player"},
      // FOLDERID_RoamingAppData {3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}
      {0x3EB685DBu, 0x65F9, 0x4CF6, "C:\\users\\player\\AppData\\Roaming"},
      // FOLDERID_ProgramData {62AB5D82-FDC1-4DC3-9A70-5B0E9E5C6EB4}
      {0x62AB5D82u, 0xFDC1, 0x4DC3, "C:\\ProgramData"},
      // FOLDERID_SavedGames {4C5C32FA-BB47-4C5C-B1A7-17439CE19972}
      {0x4C5C32FAu, 0xBB47, 0x4C5C, "C:\\users\\player\\Saved Games"},
      // FOLDERID_LocalAppDataLow {A520A1A4-1780-4FF6-BD18-167343C5AF16}
      // (Unity Application.persistentDataPath)
      {0xA520A1A4u, 0x1780, 0x4FF6, "C:\\users\\player\\AppData\\LocalLow"},
      // FOLDERID_Desktop {B4BFCC3A-DB2C-424C-B029-7FE99A87C641}
      {0xB4BFCC3Au, 0xDB2C, 0x424C, "C:\\users\\player\\Desktop"},
      // FOLDERID_Pictures {33E28130-4E1E-4676-835A-98395C3BC3BB}
      {0x33E28130u, 0x4E1E, 0x4676, "C:\\users\\player\\Pictures"},
      // FOLDERID_Music {4BD8D571-6D19-48D3-BE97-422220080E43}
      {0x4BD8D571u, 0x6D19, 0x48D3, "C:\\users\\player\\Music"},
      // FOLDERID_Videos {18989B1D-99B5-455B-841C-AB7C74E4DDFC}
      {0x18989B1Du, 0x99B5, 0x455B, "C:\\users\\player\\Videos"},
      // FOLDERID_Downloads {374DE290-123F-4565-9164-39C4925E467B}
      {0x374DE290u, 0x123F, 0x4565, "C:\\users\\player\\Downloads"},
      // FOLDERID_Public {DFDF76A2-C82A-4D63-906A-5644AC457385}
      {0xDFDF76A2u, 0xC82A, 0x4D63, "C:\\users\\Public"},
  };
  for (u32 i = 0; i < sizeof(table) / sizeof(table[0]); ++i) {
    if (id->a == table[i].a && id->b == table[i].b && id->c == table[i].c) {
      snprintf(out, cap, "%s", table[i].path);
      return 0;
    }
  }
  return 1;
}

int TRT_GUEST_ABI shell_SHGetKnownFolderPath(const u8* rfid, u32 flags,
                                             void* token, u16** path_out) {
  (void)flags; (void)token;
  if (!path_out) return E_INVALIDARG_;
  *path_out = nullptr;
  if (!rfid) return E_INVALIDARG_;
  char p8[k_max_path];
  if (knownfolder_path(rfid, p8, sizeof(p8)) != 0) {
    char guid[40];
    // print the first field for the log
    char line[128];
    guid8 id;
    memcpy(&id, rfid, sizeof(id));
    snprintf(guid, sizeof(guid), "{%08X-%04X-%04X-...}", id.a, id.b, id.c);
    snprintf(line, sizeof(line),
             "shell: SHGetKnownFolderPath %s -> E_FAIL (no mapping)",
             guid);
    log_line(line);
    { char st_line[160]; snprintf(st_line, sizeof(st_line), "strtrace: SHGetKnownFolderPath -> guid=%s path=NULL (E_FAIL)", guid); log_line(st_line); }
    return E_FAIL_;
  }
  ensure_dir(p8);
  const u32 len = (u32)strlen(p8);
  u16* buf = (u16*)malloc(((size_t)len + 1) * sizeof(u16));
  if (!buf) return (int)0x8007000Eu;  // E_OUTOFMEMORY
  utf8_to_utf16(p8, buf, len + 1);
  *path_out = buf;
  char line[160];
  snprintf(line, sizeof(line), "shell: SHGetKnownFolderPath -> %s", p8);
  log_line(line);
  { char st_line[256]; snprintf(st_line, sizeof(st_line), "strtrace: SHGetKnownFolderPath -> path_out=%p buf=%p value=\"%.128s\"", (void*)path_out, (void*)buf, p8); log_line(st_line); }
  return S_OK_;
}

// ---- SHGetMalloc: an IMalloc that is the CRT heap ----
// The SDK-exact IMalloc vtable: Alloc=3, Realloc=4, Free=5, GetSize=6,
// DidAlloc=7, HeapMinimize=8 (IUnknown 0..2).
struct malloc_vt {
  void* fns[9];
};

u32 TRT_GUEST_ABI im_QueryInterface(void*, const void*, void**) { return (u32)E_FAIL_; }
u32 TRT_GUEST_ABI im_AddRef(void*) { return 2; }
u32 TRT_GUEST_ABI im_Release(void*) { return 1; }
void* TRT_GUEST_ABI im_Alloc(void*, u32 bytes) { return bytes ? malloc(bytes) : nullptr; }
void* TRT_GUEST_ABI im_Realloc(void*, void* p, u32 bytes) { return realloc(p, bytes); }
void TRT_GUEST_ABI im_Free(void*, void* p) { free(p); }
u32 TRT_GUEST_ABI im_GetSize(void*, void*) { return 0; }
i32 TRT_GUEST_ABI im_DidAlloc(void*, void*) { return -1; }  // maybe
void TRT_GUEST_ABI im_HeapMinimize(void*) {}

malloc_vt g_malloc_vt = {
    (void*)&im_QueryInterface, (void*)&im_AddRef, (void*)&im_Release,
    (void*)&im_Alloc,          (void*)&im_Realloc, (void*)&im_Free,
    (void*)&im_GetSize,        (void*)&im_DidAlloc, (void*)&im_HeapMinimize};
void* g_malloc_obj = &g_malloc_vt;  // the object's [0] is its vtable pointer

int TRT_GUEST_ABI shell_SHGetMalloc(void** out) {
  if (!out) return E_INVALIDARG_;
  *out = &g_malloc_obj;
  return S_OK_;
}

// ---- ShellExecute: no shell on console; fail visibly and name the verb ----
int TRT_GUEST_ABI shell_ShellExecuteExW(void* info) {
  char line[128];
  snprintf(line, sizeof(line),
           "shell: ShellExecuteExW -> 0 (no shell on console; %s)",
           info ? "info struct present" : "null info");
  log_line(line);
  return 0;  // FALSE: the caller checks and falls back
}

int TRT_GUEST_ABI shell_ShellExecuteExA(void* info) {
  return shell_ShellExecuteExW(info);
}

void* TRT_GUEST_ABI shell_ShellExecuteW(void* hwnd, const u16* verb,
                                        const u16* file, const u16* args,
                                        const u16* dir, int show) {
  (void)hwnd; (void)show; (void)dir; (void)args;
  char verb8[32] = "?";
  if (verb) {
    u32 i = 0;
    for (; verb[i] && i < sizeof(verb8) - 1; ++i) verb8[i] = (char)verb[i];
    verb8[i] = 0;
  }
  char line[128];
  snprintf(line, sizeof(line),
           "shell: ShellExecuteW verb=%s -> 2 (SE_ERR_NOASSOC: no shell)",
           verb8);
  log_line(line);
  return (void*)(uintptr_t)2;  // SE_ERR_NOASSOC, a named failure
}

// ---- ILFree/ILCreateFromPath come in pairs; no shell item parsing here ----
void TRT_GUEST_ABI shell_ILFree(void* pidl) { free(pidl); }

// ---- SHCreateDirectoryExW (UnityCrashHandler): create a directory path ----
// Real semantics: creates nested dirs, returns ERROR_ALREADY_EXISTS (183)
// when the leaf already exists, ERROR_SUCCESS (0) on creation.
int TRT_GUEST_ABI shell_SHCreateDirectoryExW(void* hwnd, const u16* path,
                                             void* attr) {
  (void)hwnd; (void)attr;
  char host[1024];
  if (!path || trt_vfs_resolve_utf16(path, host, sizeof(host)) != 0) {
    char line[128];
    snprintf(line, sizeof(line), "shell: SHCreateDirectoryExW -> path unresolvable");
    log_line(line);
    return (int)0x8007000B;  // E_INVALIDARG-shaped: named failure
  }
  char line[224];
  const int rc = shellhelpers::mk_dir(host);
  if (rc == 0) {
    snprintf(line, sizeof(line), "shell: SHCreateDirectoryExW %s -> created", host);
    log_line(line);
    return 0;
  }
  if (errno == EEXIST) {
    snprintf(line, sizeof(line),
             "shell: SHCreateDirectoryExW %s -> ERROR_ALREADY_EXISTS", host);
    log_line(line);
    return 183;
  }
  snprintf(line, sizeof(line),
           "shell: SHCreateDirectoryExW %s -> mkdir failed (errno=%d)", host, errno);
  log_line(line);
  return (int)0x80070005;  // E_ACCESSDENIED-shaped: named failure
}

// ---- CommandLineToArgvW (UnityPlayer + crash handler): standard argv split
// Real semantics: returns pointer to [argv0..argvN, NULL] in one buffer;
// *lpNumArgs gets the count. Program name is argv0.
u16** TRT_GUEST_ABI shell_CommandLineToArgvW(const u16* cmdline, i32* count) {
  if (!count) return nullptr;
  *count = 0;
  if (!cmdline) return nullptr;  // real ole32 faults; we fail named
  // tokenize honoring quotes
  static u16* argv_buf[64];
  static u16 storage[64][512];
  static u16* tail[2] = {nullptr, nullptr};
  u32 nargs = 0;
  u32 i = 0;
  while (cmdline[i] && nargs < 64) {
    while (cmdline[i] == ' ' || cmdline[i] == '\t') ++i;
    if (!cmdline[i]) break;
    u32 j = 0;
    bool in_quotes = false;
    while (cmdline[i] && (in_quotes || (cmdline[i] != ' ' && cmdline[i] != '\t'))) {
      if (cmdline[i] == '"') { in_quotes = !in_quotes; ++i; continue; }
      if (j < 512 - 1) storage[nargs][j++] = cmdline[i];
      ++i;
    }
    storage[nargs][j] = 0;
    argv_buf[nargs] = storage[nargs];
    ++nargs;
  }
  tail[0] = nullptr;
  argv_buf[nargs] = nullptr;
  *count = (i32)nargs;
  char line[128];
  snprintf(line, sizeof(line), "shell: CommandLineToArgvW -> %u args", nargs);
  log_line(line);
  return argv_buf;
}

// ---- SHFileOperationW (UnityPlayer): file copy/move/delete/rename.
// v0: no shell file ops — fail VISIBLY with the op code named so the work
// item is in the log, never silently pretend success.
int TRT_GUEST_ABI shell_SHFileOperationW(void* op) {
  char line[128];
  snprintf(line, sizeof(line),
           "shell: SHFileOperationW -> 0xDE7A (named: no shell file ops yet)");
  log_line(line);
  return 0xDE7A;
}

void TRT_GUEST_ABI shell_DragAcceptFiles(void* hwnd, int accept) {
  (void)hwnd; (void)accept;
}

void TRT_GUEST_ABI shell_DragFinish(void* hdrop) {
  // DragQueryFileW hands back synthetic records (no GlobalAlloc backing), so
  // there is nothing to GlobalFree — the real contract (release the HDROP)
  // is met vacuously. Logged so a future real-HDROP implementation revisits.
  char line[128];
  snprintf(line, sizeof(line), "shell: DragFinish(%p) -> released (synthetic)",
           hdrop);
  log_line(line);
}

u32 TRT_GUEST_ABI shell_DragQueryFileW(void* hdrop, u32 idx, u16* buf, u32 cch) {
  (void)hdrop; (void)idx;
  if (buf && cch > 0) buf[0] = 0;
  return 0;
}

void* TRT_GUEST_ABI shell_SHBrowseForFolderW(const void* browse_info) {
  // No shell folder browser on the console. NULL = the user cancelled the
  // dialog (real semantics); the caller falls back to typed path entry.
  char line[128];
  snprintf(line, sizeof(line),
           "shell: SHBrowseForFolderW -> NULL (no folder picker on console; "
           "caller falls back to manual entry)");
  log_line(line);
  return nullptr;
}

int TRT_GUEST_ABI shell_SHGetPathFromIDListW(const void* pidl, u16* path) {
  (void)pidl;
  if (path) path[0] = 0;
  // No PIDLs are ever handed out (SHBrowseForFolderW returns NULL), so no
  // PIDL can resolve to a path — FALSE is the honest answer.
  return 0;
}

int TRT_GUEST_ABI shell_SHCreateItemFromParsingName(const u16* path, void* pbc,
                                                   const void* riid,
                                                   void** ppv) {
  (void)path; (void)pbc; (void)riid;
  if (ppv) *ppv = nullptr;
  return (int)0x80004001u;  // E_NOTIMPL (fail-visible)
}

int TRT_GUEST_ABI shell_SHGetPropertyStoreForWindow(void* hwnd,
                                                    const void* riid,
                                                    void** ppv) {
  (void)hwnd; (void)riid;
  if (ppv) *ppv = nullptr;
  return (int)0x80004001u;
}

int TRT_GUEST_ABI shell_SetCurrentProcessExplicitAppUserModelID(const u16* id) {
  (void)id;
  return 0;  // S_OK (AppContainer AppUserModelID is host-assigned)
}

int TRT_GUEST_ABI shell_Shell_NotifyIconGetRect(const void* nid, void* rect) {
  (void)nid;
  if (rect) memset(rect, 0, 16);
  return (int)0x80004005u;  // E_FAIL: no tray icon surface on Xbox
}

int TRT_GUEST_ABI shell_Shell_NotifyIconW(u32 msg, void* nid) {
  (void)msg; (void)nid;
  return 0;  // FALSE: no system tray on console UWP
}

// ---- PE .rsrc icon extraction --------------------------------------------
struct shell_pe_sec {
  u32 va, vsize, raw_size, raw_ptr;
};

static u16 sh_rd16(const u8* p) { u16 v; memcpy(&v, p, 2); return v; }
static u32 sh_rd32(const u8* p) { u32 v; memcpy(&v, p, 4); return v; }

static size_t sh_rva_to_off(const std::vector<shell_pe_sec>& secs, u32 rva, size_t total) {
  for (const auto& s : secs) {
    const u32 span = s.vsize ? s.vsize : s.raw_size;
    if (span && rva >= s.va && rva - s.va < span) {
      const size_t off = (size_t)s.raw_ptr + (size_t)(rva - s.va);
      if (off < total) return off;
    }
  }
  return (size_t)-1;
}

static bool sh_resolve_open_path(const char* raw_path, char* out, size_t out_cap) {
  if (!raw_path || !raw_path[0]) return false;
  if (raw_path[1] == ':' && (raw_path[2] == '\\' || raw_path[2] == '/')) {
    u16 w[512];
    size_t i = 0;
    for (; raw_path[i] && i + 1 < 512; ++i) w[i] = (u16)(u8)raw_path[i];
    w[i] = 0;
    if (trt_vfs_resolve_utf16(w, out, out_cap) == 0) return true;
  }
  snprintf(out, out_cap, "%s", raw_path);
  return true;
}

struct pe_icon_dim { int w; int h; };

static std::vector<pe_icon_dim> scan_pe_group_icons(const char* path) {
  std::vector<pe_icon_dim> out;
  char host[1024];
  if (!sh_resolve_open_path(path, host, sizeof(host))) return out;
  FILE* f = fopen(host, "rb");
  if (!f) return out;
  fseek(f, 0, SEEK_END);
  long fsz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (fsz <= 128 || fsz > 64 * 1024 * 1024) {
    fclose(f);
    return out;
  }
  std::vector<u8> buf((size_t)fsz);
  size_t got = fread(buf.data(), 1, (size_t)fsz, f);
  fclose(f);
  const u8* d = buf.data();
  const size_t total = got;
  if (total < sizeof(trt_dos_header)) return out;
  trt_dos_header dos{};
  memcpy(&dos, d, sizeof(dos));
  if (dos.e_magic != 0x5A4D) return out;
  const size_t nt = dos.e_lfanew;
  if (nt + 4 + sizeof(trt_file_header) + 2 > total) return out;
  if (sh_rd32(d + nt) != 0x00004550u) return out;
  trt_file_header fh{};
  memcpy(&fh, d + nt + 4, sizeof(fh));
  const size_t opt_off = nt + 4 + sizeof(fh);
  const u16 magic = sh_rd16(d + opt_off);
  const bool pe32 = (magic == TRT_PE_OPT32_MAGIC);
  const bool pe64 = (magic == 0x020b);
  if (!pe32 && !pe64) return out;
  const size_t dirs_off = opt_off + (pe32 ? TRT_PE32_OPT_DIRS_OFF : TRT_PE64_OPT_DIRS_OFF);
  if (dirs_off + sizeof(trt_data_directory) * TRT_PE_NUM_DIRECTORIES > total) return out;
  trt_data_directory dirs[TRT_PE_NUM_DIRECTORIES];
  memcpy(dirs, d + dirs_off, sizeof(dirs));
  const u32 rsrc_rva = dirs[2 /*IMAGE_DIRECTORY_ENTRY_RESOURCE*/].virtual_address;
  const u32 rsrc_sz = dirs[2].size;
  if (!rsrc_rva || !rsrc_sz) return out;

  std::vector<shell_pe_sec> secs;
  const size_t sec_off = opt_off + fh.size_of_optional_header;
  for (u16 i = 0; i < fh.number_of_sections; ++i) {
    const size_t o = sec_off + (size_t)i * sizeof(trt_section_header);
    if (o + sizeof(trt_section_header) > total) break;
    trt_section_header sh{};
    memcpy(&sh, d + o, sizeof(sh));
    secs.push_back({sh.virtual_address, sh.virtual_size,
                    sh.size_of_raw_data, sh.pointer_to_raw_data});
  }
  const size_t rsrc_base = sh_rva_to_off(secs, rsrc_rva, total);
  if (rsrc_base == (size_t)-1 || rsrc_base + 16 > total) return out;

  const u16 t_named = sh_rd16(d + rsrc_base + 12);
  const u16 t_ided = sh_rd16(d + rsrc_base + 14);
  const u32 t_cnt = (u32)(t_named + t_ided);
  for (u32 ti = 0; ti < t_cnt; ++ti) {
    const size_t eo = rsrc_base + 16 + (size_t)ti * 8;
    if (eo + 8 > total) break;
    const u32 id = sh_rd32(d + eo);
    const u32 val = sh_rd32(d + eo + 4);
    if ((id & 0x80000000u) == 0 && (id & 0xFFFFu) == 14u /*RT_GROUP_ICON*/ &&
        (val & 0x80000000u) != 0) {
      const size_t gdir = rsrc_base + (size_t)(val & 0x7FFFFFFFu);
      if (gdir + 16 > total) break;
      const u32 gcnt = (u32)sh_rd16(d + gdir + 12) + sh_rd16(d + gdir + 14);
      for (u32 gi = 0; gi < gcnt; ++gi) {
        const size_t geo = gdir + 16 + (size_t)gi * 8;
        if (geo + 8 > total) break;
        const u32 gval = sh_rd32(d + geo + 4);
        int iw = 32, ih = 32;
        if (gval & 0x80000000u) {
          const size_t ldir = rsrc_base + (size_t)(gval & 0x7FFFFFFFu);
          if (ldir + 24 <= total) {
            const u32 lcnt = (u32)sh_rd16(d + ldir + 12) + sh_rd16(d + ldir + 14);
            if (lcnt > 0) {
              const u32 dval = sh_rd32(d + ldir + 16 + 4);
              if ((dval & 0x80000000u) == 0) {
                const size_t de = rsrc_base + (size_t)dval;
                if (de + 16 <= total) {
                  const u32 data_off = (u32)sh_rva_to_off(secs, sh_rd32(d + de), total);
                  const u32 data_sz = sh_rd32(d + de + 4);
                  if (data_off != (u32)-1 && (size_t)data_off + 20 <= total && data_sz >= 20) {
                    const u16 grp_cnt = sh_rd16(d + data_off + 4);
                    if (grp_cnt > 0) {
                      const u8 w0 = d[data_off + 6];
                      const u8 h0 = d[data_off + 7];
                      iw = w0 ? (int)w0 : 256;
                      ih = h0 ? (int)h0 : 256;
                    }
                  }
                }
              }
            }
          }
        }
        out.push_back({iw, ih});
      }
      break;
    }
  }
  return out;
}

u32 extract_icons_common(const char* path, int index, void** large,
                         void** small, u32 count) {
  if (large && count > 0) memset(large, 0, count * sizeof(void*));
  if (small && count > 0) memset(small, 0, count * sizeof(void*));
  const std::vector<pe_icon_dim> icons = scan_pe_group_icons(path);
  if (index == -1) return (u32)icons.size();
  if (index < 0 || (size_t)index >= icons.size() || count == 0 || (!large && !small))
    return 0;
  u32 extracted = 0;
  for (u32 i = 0; i < count && (size_t)index + i < icons.size(); ++i) {
    const auto& dim = icons[(size_t)index + i];
    if (large) large[i] = trt_user32_icon_alloc(dim.w, dim.h);
    if (small) small[i] = trt_user32_icon_alloc(16, 16);
    ++extracted;
  }
  return extracted;
}

u32 TRT_GUEST_ABI shell_ExtractIconExW(const u16* file, int index, void** large,
                                       void** small, u32 count) {
  char nm[512] = "";
  if (file && trt_utf16_to_utf8(file, nm, sizeof(nm)) != 0) nm[0] = 0;
  const u32 got = extract_icons_common(nm, index, large, small, count);
  char line[256];
  snprintf(line, sizeof(line),
           "shell32: ExtractIconExW(\"%s\", index=%d, n=%u) -> %u icon(s)",
           nm, index, count, got);
  log_line(line);
  return got;
}

u32 TRT_GUEST_ABI shell_ExtractIconExA(const char* file, int index, void** large,
                                       void** small, u32 count) {
  const u32 got = extract_icons_common(file ? file : "", index, large, small, count);
  char line[256];
  snprintf(line, sizeof(line),
           "shell32: ExtractIconExA(\"%s\", index=%d, n=%u) -> %u icon(s)",
           file ? file : "", index, count, got);
  log_line(line);
  return got;
}

void* TRT_GUEST_ABI shell_ExtractIconW(void* inst, const u16* file, u32 index) {
  (void)inst;
  char nm[512] = "";
  if (file && trt_utf16_to_utf8(file, nm, sizeof(nm)) != 0) nm[0] = 0;
  if (index == 0xFFFFFFFFu) {
    const u32 total = extract_icons_common(nm, -1, nullptr, nullptr, 0);
    return (void*)(uintptr_t)total;
  }
  void* ico = nullptr;
  extract_icons_common(nm, (int)index, &ico, nullptr, 1);
  return ico;
}

void* TRT_GUEST_ABI shell_ExtractIconA(void* inst, const char* file, u32 index) {
  (void)inst;
  if (index == 0xFFFFFFFFu) {
    const u32 total = extract_icons_common(file ? file : "", -1, nullptr, nullptr, 0);
    return (void*)(uintptr_t)total;
  }
  void* ico = nullptr;
  extract_icons_common(file ? file : "", (int)index, &ico, nullptr, 1);
  return ico;
}

}  // namespace

extern "C" {
int trt_bridge_register_shell(void) {
  static const trt_named_fn k_fns[] = {
      {"SHGetFolderPathW", (void*)&shell_SHGetFolderPathW},
      {"SHGetFolderPathA", (void*)&shell_SHGetFolderPathA},
      {"SHGetKnownFolderPath", (void*)&shell_SHGetKnownFolderPath},
      {"SHGetMalloc", (void*)&shell_SHGetMalloc},
      {"ShellExecuteExW", (void*)&shell_ShellExecuteExW},
      {"ShellExecuteExA", (void*)&shell_ShellExecuteExA},
      {"ShellExecuteW", (void*)&shell_ShellExecuteW},
      {"ILFree", (void*)&shell_ILFree},
      {"SHCreateDirectoryExW", (void*)&shell_SHCreateDirectoryExW},
      {"CommandLineToArgvW", (void*)&shell_CommandLineToArgvW},
      {"SHFileOperationW", (void*)&shell_SHFileOperationW},
      {"DragAcceptFiles", (void*)&shell_DragAcceptFiles},
      {"DragQueryFileW", (void*)&shell_DragQueryFileW},
      {"DragFinish", (void*)&shell_DragFinish},
      {"SHBrowseForFolderW", (void*)&shell_SHBrowseForFolderW},
      {"SHGetPathFromIDListW", (void*)&shell_SHGetPathFromIDListW},
      {"SHCreateItemFromParsingName", (void*)&shell_SHCreateItemFromParsingName},
      {"SHGetPropertyStoreForWindow", (void*)&shell_SHGetPropertyStoreForWindow},
      {"SetCurrentProcessExplicitAppUserModelID",
       (void*)&shell_SetCurrentProcessExplicitAppUserModelID},
      {"Shell_NotifyIconGetRect", (void*)&shell_Shell_NotifyIconGetRect},
      {"Shell_NotifyIconW", (void*)&shell_Shell_NotifyIconW},
      {"ExtractIconExW", (void*)&shell_ExtractIconExW},
      {"ExtractIconExA", (void*)&shell_ExtractIconExA},
      {"ExtractIconW", (void*)&shell_ExtractIconW},
      {"ExtractIconA", (void*)&shell_ExtractIconA},
  };
  trt_module_register("shell32.dll", TRT_ROUTE_BUILTIN, k_fns,
                      (int)(sizeof(k_fns) / sizeof(k_fns[0])));
  // shfolder.dll is a thin shim onto SHGetFolderPath — same export set
  trt_module_register("shfolder.dll", TRT_ROUTE_BUILTIN, k_fns,
                      (int)(sizeof(k_fns) / sizeof(k_fns[0])));
  return 0;
}

}  // extern "C"
