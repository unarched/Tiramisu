// tiramisu/src/host/settings.cpp
#include "settings.h"

#include "../trt/trt.h"

#include <cctype>
#include <charconv>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace longan {

namespace {

std::mutex g_mu;
host_settings g_base;
host_settings g_live;
std::string g_profile_ini;
std::string g_env_ini;
// <LocalState>\cache\shaders, resolved in settings_load(). Read by the bridge
// through trt_settings_shader_cache_dir() so a translation done in one launch
// is a hit in the next.
std::string g_shader_cache_dir;

#ifdef _WIN32
const char k_sep = '\\';
#else
const char k_sep = '/';  // offline-test path (Linux)
#endif

int clampi(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

// One list drives both dashboard reads and writes, so a visible setting
// cannot quietly disappear from one side of the HTTP API.
template <typename T>
struct dashboard_setting {
  const char* key;
  T host_settings::*member;
};
constexpr dashboard_setting<bool> dashboard_flags[] = {
    {"pad_vibration", &host_settings::pad_vibration},
    {"win11_personality", &host_settings::win11_personality},
    {"write_watch", &host_settings::write_watch},
    {"steam_auth", &host_settings::steam_auth},
    {"show_qr", &host_settings::show_qr},
    {"show_fps", &host_settings::show_fps},
    {"show_sysinfo", &host_settings::show_sysinfo},
    {"quick_menu_enabled", &host_settings::quick_menu_enabled},
    {"vsync", &host_settings::vsync},
    {"shader_cache", &host_settings::shader_cache},
    {"fsb_decode", &host_settings::fsb_decode},
};
constexpr dashboard_setting<int> dashboard_numbers[] = {
    {"mouse_speed", &host_settings::mouse_speed},
    {"wheel_speed", &host_settings::wheel_speed},
    {"os_major", &host_settings::os_major},
    {"os_minor", &host_settings::os_minor},
    {"os_build", &host_settings::os_build},
    {"log_lines", &host_settings::log_lines},
    {"frame_rate_cap", &host_settings::frame_rate_cap},
    {"resolution_scale", &host_settings::resolution_scale},
    {"memory_budget_mb", &host_settings::memory_budget_mb},
    {"input_deadzone", &host_settings::input_deadzone},
    {"audio_buffer_ms", &host_settings::audio_buffer_ms},
    {"texture_quality", &host_settings::texture_quality},
};
constexpr dashboard_setting<std::string> dashboard_text[] = {
    {"default_input", &host_settings::default_input},
    {"network_games_root", &host_settings::network_games_root},
};

void skip_json_space(std::string_view& input) {
  const auto first = input.find_first_not_of(" \t\r\n");
  input.remove_prefix(first == std::string_view::npos ? input.size() : first);
}

bool take_json(std::string_view& input, char expected) {
  skip_json_space(input);
  if (input.empty() || input.front() != expected) return false;
  input.remove_prefix(1);
  return true;
}

bool read_json_hex(std::string_view& input, uint32_t& value) {
  if (input.size() < 4) return false;
  value = 0;
  for (char c : input.substr(0, 4)) {
    if (c >= '0' && c <= '9') value = value * 16 + (c - '0');
    else if (c >= 'a' && c <= 'f') value = value * 16 + (c - 'a' + 10);
    else if (c >= 'A' && c <= 'F') value = value * 16 + (c - 'A' + 10);
    else return false;
  }
  input.remove_prefix(4);
  return true;
}

bool read_json_unicode(std::string_view& input, std::string& text) {
  uint32_t code;
  if (!read_json_hex(input, code)) return false;
  if (code >= 0xD800 && code <= 0xDBFF) {
    if (!input.starts_with("\\u")) return false;
    input.remove_prefix(2);
    uint32_t low;
    if (!read_json_hex(input, low) || low < 0xDC00 || low > 0xDFFF) return false;
    code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
  } else if (code >= 0xDC00 && code <= 0xDFFF) {
    return false;
  }

  if (code < 0x80) {
    text.push_back(static_cast<char>(code));
    return true;
  }
  const int extra = code < 0x800 ? 1 : code < 0x10000 ? 2 : 3;
  const unsigned prefix[] = {0, 0xC0, 0xE0, 0xF0};
  text.push_back(static_cast<char>(prefix[extra] | (code >> (6 * extra))));
  for (int n = extra - 1; n >= 0; --n)
    text.push_back(static_cast<char>(0x80 | ((code >> (6 * n)) & 0x3F)));
  return true;
}

bool read_json_string(std::string_view& input, std::string& text) {
  if (!take_json(input, '"')) return false;
  text.clear();
  while (!input.empty()) {
    const unsigned char c = input.front();
    input.remove_prefix(1);
    if (c == '"') return true;
    if (c < 0x20) return false;
    if (c != '\\') {
      text.push_back(static_cast<char>(c));
      continue;
    }
    if (input.empty()) return false;
    const char escaped = input.front();
    input.remove_prefix(1);
    switch (escaped) {
      case '"': case '\\': case '/': text.push_back(escaped); break;
      case 'b': text.push_back('\b'); break;
      case 'f': text.push_back('\f'); break;
      case 'n': text.push_back('\n'); break;
      case 'r': text.push_back('\r'); break;
      case 't': text.push_back('\t'); break;
      case 'u': if (!read_json_unicode(input, text)) return false; break;
      default: return false;
    }
  }
  return false;
}

std::string quote_dashboard_string(std::string_view value) {
  std::string json = "\"";
  for (unsigned char c : value) {
    if (c == '"' || c == '\\') json += '\\';
    if (c < 0x20) {
      char escaped[7];
      snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned>(c));
      json += escaped;
    } else {
      json += static_cast<char>(c);
    }
  }
  return json + '"';
}

template <typename T, size_t N>
bool assign_dashboard_value(host_settings& settings, std::string_view key,
                            const T& value, const dashboard_setting<T> (&entries)[N]) {
  for (const auto& entry : entries) {
    if (key == entry.key) {
      settings.*entry.member = value;
      return true;
    }
  }
  return false;
}

bool valid_ini_text(std::string_view text) {
  return text.find_first_of("\r\n") == std::string_view::npos &&
         text.find('\0') == std::string_view::npos;
}

bool read_dashboard_number(std::string_view token, int& value, bool& integer) {
  // The dashboard uses integers. Accept valid decimal and exponent syntax
  // without applying those values to integer settings.
  const auto end_integer = token.find_first_of(".eE");
  const auto integer_token = token.substr(0, end_integer);
  const bool negative = integer_token.starts_with('-');
  auto digits = integer_token.substr(negative ? 1 : 0);
  if (digits.empty() || (digits.front() == '0' && digits.size() > 1) ||
      digits.find_first_not_of("0123456789") != std::string_view::npos) return false;
  integer = end_integer == std::string_view::npos;
  if (integer) {
    int raw = 0;
    const auto result = std::from_chars(integer_token.data(),
                                        integer_token.data() + integer_token.size(), raw);
    value = result.ec == std::errc::result_out_of_range
        ? (negative ? -100000 : 100000) : clampi(raw, -100000, 100000);
    return true;
  }

  auto suffix = token.substr(end_integer);
  if (suffix.front() == '.') {
    suffix.remove_prefix(1);
    const auto count = suffix.find_first_not_of("0123456789");
    if (count == 0 || suffix.empty()) return false;
    if (count == std::string_view::npos) return true;
    suffix.remove_prefix(count);
  }
  if (suffix.empty() || (suffix.front() != 'e' && suffix.front() != 'E')) return false;
  suffix.remove_prefix(1);
  if (!suffix.empty() && (suffix.front() == '+' || suffix.front() == '-'))
    suffix.remove_prefix(1);
  return !suffix.empty() && suffix.find_first_not_of("0123456789") == std::string_view::npos;
}

std::string trim(const std::string& s) {
  size_t a = 0, b = s.size();
  while (a < b && (unsigned char)s[a] <= ' ') ++a;
  while (b > a && (unsigned char)s[b - 1] <= ' ') --b;
  return s.substr(a, b - a);
}

// A profile path is always <dir>/tiramisu.profile.ini, with separators
// normalized so a Windows-style game dir works on the offline (Linux) gate.
std::string profile_path(std::string dir) {
  // Normalize to the separator this build can actually fopen: a game dir is
  // written Windows-style on the console, but the offline gate runs on Linux.
#ifdef _WIN32
  const char sep = '\\';
  for (char& c : dir) if (c == '/') c = '\\';
#else
  const char sep = '/';
  for (char& c : dir) if (c == '\\') c = '/';
#endif
  if (!dir.empty() && dir.back() != sep) dir += sep;
  return dir + "tiramisu.profile.ini";
}

int make_dir(std::string dir) {
  // Strip the profile filename, then create each missing component: a first
  // run writes into a nested LocalState path that may not exist yet.
  const std::string suffix = "tiramisu.profile.ini";
  dir = profile_path(dir);
  dir.resize(dir.size() - suffix.size());
  while (dir.size() > 1 && (dir.back() == '/' || dir.back() == '\\'))
    dir.pop_back();
  if (dir.empty()) return -1;
#ifdef _WIN32
  const char sep = '\\';
#else
  const char sep = '/';
#endif
  std::string cur;
  for (size_t i = 0; i <= dir.size(); ++i) {
    const bool at_sep = (i == dir.size()) || (dir[i] == sep);
    if (at_sep && !cur.empty()) {
#ifdef _WIN32
      _mkdir(cur.c_str());  // already-there is fine; the fopen decides
#else
      mkdir(cur.c_str(), 0755);
#endif
    }
    if (i < dir.size()) cur += dir[i];
  }
  return 0;
}

// g_mu is held by the caller. Only g_base is serialized, so a guest
// override or environment value never leaks into the next session's INI.
int rebuild_live_settings() {
  g_live = g_base;
  const int profile_keys = g_live.apply_ini(g_profile_ini);
  return profile_keys + g_live.apply_ini(g_env_ini);
}

bool write_ini_atomic(const std::string& path, const std::string& text) {
  const auto temporary = path + ".tmp";
  FILE* file = fopen(temporary.c_str(), "wb");
  if (!file) return false;
  const bool written = fwrite(text.data(), 1, text.size(), file) == text.size();
  const bool closed = fclose(file) == 0;
  bool committed = false;
  if (written && closed) {
#ifdef _WIN32
    committed = MoveFileExA(temporary.c_str(), path.c_str(),
                            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != 0;
#else
    committed = rename(temporary.c_str(), path.c_str()) == 0;
#endif
  }
  if (!committed) remove(temporary.c_str());
  return committed;
}

} // namespace

std::string host_settings::to_ini() const {
  char buf[640];
  std::string s;
  s += "# Tiramisu host settings — edited from the dashboard (TV or web).\n";
  s += "# Missing keys keep their built-in defaults.\n";
  snprintf(buf, sizeof(buf), "default_input=%s\n", default_input.c_str());
  s += buf;
  snprintf(buf, sizeof(buf), "mouse_speed=%d\nwheel_speed=%d\n",
           mouse_speed, wheel_speed);
  s += buf;
  s += pad_vibration ? "pad_vibration=1\n" : "pad_vibration=0\n";
  snprintf(buf, sizeof(buf), "os_major=%d\nos_minor=%d\nos_build=%d\n",
           os_major, os_minor, os_build);
  s += buf;
  s += win11_personality ? "win11_personality=1\n" : "win11_personality=0\n";
  s += write_watch ? "write_watch=1\n" : "write_watch=0\n";
  s += steam_auth ? "steam_auth=1\n" : "steam_auth=0\n";
  s += fsb_decode ? "fsb_decode=1\n" : "fsb_decode=0\n";
  s += crash_report ? "crash_report=1\n" : "crash_report=0\n";
  s += show_qr ? "show_qr=1\n" : "show_qr=0\n";
  s += show_fps ? "show_fps=1\n" : "show_fps=0\n";
  s += show_sysinfo ? "show_sysinfo=1\n" : "show_sysinfo=0\n";
  s += quick_menu_enabled ? "quick_menu_enabled=1\n" : "quick_menu_enabled=0\n";
  s += "launch_args=";
  s += launch_args;
  s += "\n";
  s += "required_services=";
  s += required_services;
  s += "\n";
  s += "network_games_root=";
  s += network_games_root;
  s += "\n";
  snprintf(buf, sizeof(buf), "log_lines=%d\n", log_lines);
  s += buf;
  snprintf(buf, sizeof(buf),
           "resolution_scale=%d\nframe_rate_cap=%d\nmemory_budget_mb=%d\n",
           resolution_scale, frame_rate_cap, memory_budget_mb);
  s += buf;
  s += vsync ? "vsync=1\n" : "vsync=0\n";
  s += shader_cache ? "shader_cache=1\n" : "shader_cache=0\n";
  snprintf(buf, sizeof(buf),
           "audio_buffer_ms=%d\ninput_deadzone=%d\ntexture_quality=%d\n",
           audio_buffer_ms, input_deadzone, texture_quality);
  s += buf;
  return s;
}

int host_settings::apply_ini(const std::string& text) {
  int applied = 0;
  size_t pos = 0;
  while (pos < text.size()) {
    size_t eol = text.find('\n', pos);
    if (eol == std::string::npos) eol = text.size();
    std::string line = trim(text.substr(pos, eol - pos));
    pos = eol + 1;
    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    const size_t eq = line.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = trim(line.substr(0, eq));
    const std::string val = trim(line.substr(eq + 1));
    if (key.empty()) continue;
    if (key == "default_input") {
      if (val != "auto" && val != "controller" && val != "kbm" && val != "pad2kbm")
        continue;
      default_input = val;
    } else if (key == "launch_args") {
      // Quotes are for readability in the file; the guest gets the raw text.
      std::string v = val;
      if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
        v = v.substr(1, v.size() - 2);
        v = trim(v);
      }
      launch_args = v.size() > 512 ? v.substr(0, 512) : v;
    } else if (key == "required_services") {
      required_services =
          val.size() > 256 ? val.substr(0, 256) : val;
    } else if (key == "network_games_root") {
      network_games_root = val.size() > 1024 ? val.substr(0, 1024) : val;
    } else if (key == "mouse_speed") {
      mouse_speed = clampi(atoi(val.c_str()), 1, 100);
    } else if (key == "wheel_speed") {
      wheel_speed = clampi(atoi(val.c_str()), 1, 100);
    } else if (key == "pad_vibration") {
      pad_vibration = (val == "1" || val == "true");
    } else if (key == "os_major") {
      os_major = clampi(atoi(val.c_str()), 5, 12);
    } else if (key == "os_minor") {
      os_minor = clampi(atoi(val.c_str()), 0, 99);
    } else if (key == "os_build") {
      os_build = clampi(atoi(val.c_str()), 0, 99999);
    } else if (key == "win11_personality") {
      win11_personality = (val == "1" || val == "true");
    } else if (key == "write_watch") {
      write_watch = (val == "1" || val == "true");
    } else if (key == "steam_auth") {
      steam_auth = (val == "1" || val == "true");
    } else if (key == "fsb_decode") {
      fsb_decode = (val == "1" || val == "true");
    } else if (key == "crash_report") {
      crash_report = (val == "1" || val == "true");
    } else if (key == "show_qr") {
      show_qr = (val == "1" || val == "true");
    } else if (key == "show_fps") {
      show_fps = (val == "1" || val == "true");
    } else if (key == "show_sysinfo") {
      show_sysinfo = (val == "1" || val == "true");
    } else if (key == "quick_menu_enabled") {
      quick_menu_enabled = (val == "1" || val == "true");
    } else if (key == "log_lines") {
      log_lines = clampi(atoi(val.c_str()), 4, 40);
    } else if (key == "resolution_scale") {
      resolution_scale = clampi(atoi(val.c_str()), 50, 200);
    } else if (key == "frame_rate_cap") {
      frame_rate_cap = clampi(atoi(val.c_str()), 0, 120);
    } else if (key == "memory_budget_mb") {
      memory_budget_mb = clampi(atoi(val.c_str()), 1024, 8192);
    } else if (key == "vsync") {
      vsync = (val == "1" || val == "true");
    } else if (key == "shader_cache") {
      shader_cache = (val == "1" || val == "true");
    } else if (key == "audio_buffer_ms") {
      audio_buffer_ms = clampi(atoi(val.c_str()), 10, 50);
    } else if (key == "input_deadzone") {
      input_deadzone = clampi(atoi(val.c_str()), 0, 50);
    } else if (key == "texture_quality") {
      texture_quality = clampi(atoi(val.c_str()), 0, 3);
    } else {
      continue;  // Unknown keys do not count toward the applied total.
    }
    ++applied;
  }
  return applied;
}

// Service ids this host can honestly claim. A per-title profile naming
// anything else gets a warning instead of a mystery failure later.
bool service_known(const std::string& id) {
  static const char* const k_known[] = {"xinput", "gamepad", "wasapi",
                                        "audio",  "steam",   "fmod",
                                        "dinput", "ole32",   "winrt"};
  for (const char* k : k_known)
    if (id == k) return true;
  return false;
}

// NOTE: settings.cpp is linked on its own by tests/test_settings.cpp, so it
// must not reference the engine. The trt layer owns the FSB5 console decode
// gate; main.cpp applies `fsb_decode` to it after each ini load.
static std::string settings_environment_ini() {
  static const char* const k_keys[] = {
      "default_input",  "launch_args",        "required_services",
      "mouse_speed",    "wheel_speed",        "pad_vibration",
      "os_major",       "os_minor",           "os_build",
      "win11_personality", "write_watch",     "steam_auth",
      "fsb_decode",     "crash_report",       "resolution_scale",
      "frame_rate_cap", "memory_budget_mb",   "vsync",
      "shader_cache",   "audio_buffer_ms",    "input_deadzone",
      "texture_quality", "log_lines"};
  std::string text;
  for (const char* key : k_keys) {
    std::string env = "TIRAMISU_";
    for (const char* p = key; *p; ++p)
      env += (char)toupper((unsigned char)*p);
    const char* v = getenv(env.c_str());
    if (!v || !*v) continue;
    text += key;
    text += '=';
    text += v;
    text += '\n';
  }
  return text;
}

int settings_load(const std::string& local_state) {
  std::lock_guard<std::mutex> lock(g_mu);
  g_base = {};
  if (!local_state.empty())
    g_shader_cache_dir = local_state + k_sep + "cache" + k_sep + "shaders";
  int applied = 0;
  if (FILE* f = fopen((local_state + k_sep + "settings.ini").c_str(), "rb")) {
    std::string text;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    const bool complete = !ferror(f);
    fclose(f);
    if (complete) applied = g_base.apply_ini(text);
  }
  g_env_ini = settings_environment_ini();
  return applied + rebuild_live_settings();
}

int settings_apply_env() {
  std::lock_guard<std::mutex> lock(g_mu);
  g_env_ini = settings_environment_ini();
  rebuild_live_settings();
  host_settings env{};
  return env.apply_ini(g_env_ini);
}

void settings_clear_profile() {
  std::lock_guard<std::mutex> lock(g_mu);
  if (g_profile_ini.empty()) return;
  g_profile_ini.clear();
  rebuild_live_settings();
}

host_settings settings_get_global() {
  std::lock_guard<std::mutex> lock(g_mu);
  return g_base;
}

std::string settings_title_profile_dir(const std::string& local_state,
                                      const std::string& source_path) {
  // Use the source path rather than a display title that can collide across
  // library roots. Normalize separators and native Windows casing.
  uint64_t hash = 14695981039346656037ULL;
  for (unsigned char c : source_path) {
    if (c == '\\') c = '/';
#ifdef _WIN32
    if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
#endif
    hash ^= c;
    hash *= 1099511628211ULL;
  }
  char key[24];
  snprintf(key, sizeof(key), "title-%016llx", static_cast<unsigned long long>(hash));
  return local_state + k_sep + "profiles" + k_sep + key;
}

int settings_unknown_services(const std::string& list, std::string* unknown) {
  if (unknown) unknown->clear();
  int bad = 0;
  size_t pos = 0;
  while (pos <= list.size()) {
    size_t comma = list.find(',', pos);
    if (comma == std::string::npos) comma = list.size();
    const std::string id = trim(list.substr(pos, comma - pos));
    pos = comma + 1;
    if (id.empty()) continue;
    if (service_known(id)) continue;
    ++bad;
    if (unknown) {
      if (!unknown->empty()) *unknown += ",";
      *unknown += id;
    }
  }
  return bad;
}

int settings_save(const std::string& local_state) {
  std::lock_guard<std::mutex> lock(g_mu);
  return write_ini_atomic(local_state + k_sep + "settings.ini", g_base.to_ini())
             ? 0 : -1;
}

std::string settings_read_user_profile(const std::string& dir) {
  if (dir.empty()) return {};
  FILE* file = fopen(profile_path(dir).c_str(), "rb");
  if (!file) return {};
  std::string result;
  char block[1024];
  size_t count;
  while ((count = fread(block, 1, sizeof(block), file)) > 0) {
    result.append(block, count);
    if (result.size() > 64 * 1024) break;
  }
  if (ferror(file) || result.size() > 64 * 1024) result.clear();
  fclose(file);
  return result;
}

bool settings_write_user_profile(const std::string& dir, const std::string& text) {
  if (dir.empty() || text.size() > 64 * 1024 || text.find('\0') != std::string::npos)
    return false;
  std::lock_guard<std::mutex> lock(g_mu);
  make_dir(dir);
  return write_ini_atomic(profile_path(dir), text);
}

int settings_load_profile(const std::string& game_dir, const std::string& user_profile_dir) {
  auto profile = settings_read_user_profile(game_dir);
  if (!user_profile_dir.empty() && user_profile_dir != game_dir)
    profile += '\n' + settings_read_user_profile(user_profile_dir);
  std::lock_guard<std::mutex> lock(g_mu);
  g_profile_ini = std::move(profile);
  g_env_ini = settings_environment_ini();
  return rebuild_live_settings();
}

int settings_write_profile_stub(const std::string& dir,
                                const std::string& title) {
  std::lock_guard<std::mutex> lock(g_mu);
  const std::string path = profile_path(dir);
  if (FILE* exists = fopen(path.c_str(), "rb")) {
    fclose(exists);
    return 0;  // never clobber a title the user already tuned
  }
  make_dir(dir);  // parent usually exists; a failure shows up as the write below

  std::string text;
  text += "# Tiramisu per-title overrides — " + title + "\n";
  text += "# Applied on top of settings.ini for this title only. Missing keys\n";
  text += "# keep the global value, so this file can stay short.\n";
  text += "\n# Arguments passed to the game (beats the synthesizer's guesses).\n";
  text += "# launch_args=\n";
  text += "\n# Any settings.ini key works here, for example:\n";
  text += "# resolution_scale=100\n";
  text += "# frame_rate_cap=60\n";
  text += "# default_input=auto\n";
  text += "# input_deadzone=15\n";
  text += "# audio_buffer_ms=20\n";
  text += "# vsync=1\n";
  text += "# win11_personality=0\n";
  return write_ini_atomic(path, text) ? 1 : -1;
}

std::string dashboard_settings_json(const host_settings& settings) {
  std::string json = "{";
  auto add = [&](const char* key, const std::string& encoded) {
    if (json.size() > 1) json += ',';
    json += '"';
    json += key;
    json += "\":";
    json += encoded;
  };
  for (const auto& entry : dashboard_flags)
    add(entry.key, settings.*entry.member ? "true" : "false");
  for (const auto& entry : dashboard_numbers)
    add(entry.key, std::to_string(settings.*entry.member));
  for (const auto& entry : dashboard_text)
    add(entry.key, quote_dashboard_string(settings.*entry.member));
  return json + '}';
}

bool apply_dashboard_settings(std::string_view input, host_settings& settings) {
  if (!take_json(input, '{')) return false;
  host_settings updated = settings;
  if (!take_json(input, '}')) {
    do {
      std::string key;
      if (!read_json_string(input, key) || !take_json(input, ':')) return false;
      skip_json_space(input);
      if (input.empty()) return false;
      if (input.front() == '"') {
        std::string text;
        if (!read_json_string(input, text)) return false;
        if (assign_dashboard_value(updated, key, text, dashboard_text) &&
            !valid_ini_text(text)) return false;
      } else {
        const auto token = input.substr(0, input.find_first_of(" \t\r\n,}"));
        if (token == "true" || token == "false") {
          assign_dashboard_value(updated, key, token == "true", dashboard_flags);
        } else if (token != "null") {
          int number;
          bool integer;
          if (!read_dashboard_number(token, number, integer)) return false;
          if (integer) assign_dashboard_value(updated, key, number, dashboard_numbers);
        }
        input.remove_prefix(token.size());
      }
    } while (take_json(input, ','));
    if (!take_json(input, '}')) return false;
  }
  skip_json_space(input);
  if (!input.empty()) return false;
  settings = std::move(updated);
  return true;
}

bool settings_store(const host_settings& s, const std::string& local_state) {
  std::lock_guard<std::mutex> lock(g_mu);
  // Persist the same bounded values a reload would produce. One validation
  // path covers settings entered in the TV UI, web UI, and INI file.
  for (const auto* text : {&s.default_input, &s.launch_args, &s.required_services, &s.network_games_root})
    if (!valid_ini_text(*text)) return false;
  host_settings c;
  c.apply_ini(s.to_ini());
  if (!write_ini_atomic(local_state + k_sep + "settings.ini", c.to_ini()))
    return false;
  g_base = std::move(c);
  rebuild_live_settings();
  return true;
}

host_settings settings_get() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live;  // by value: callers must not race a concurrent settings_store
}

// ---- bridge-facing getters (lock-free snapshot of the ints that matter) ----
void trt_settings_os(int* major, int* minor, int* build) {
  std::lock_guard<std::mutex> lk(g_mu);
  int mj = g_live.os_major, mn = g_live.os_minor, bd = g_live.os_build;
  if (g_live.win11_personality && bd < 22000) bd = 22000;
  if (major) *major = mj;
  if (minor) *minor = mn;
  if (build) *build = bd;
}

bool trt_settings_write_watch() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.write_watch;
}

bool trt_settings_pad_vibration() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.pad_vibration;
}

bool trt_settings_show_fps() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.show_fps;
}

bool trt_settings_show_sysinfo() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.show_sysinfo;
}

bool trt_settings_quick_menu_enabled() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.quick_menu_enabled;
}

// Weak-linked wrapper consumed by bridge_vulkan's shader cache
// (bridge_vulkan.cpp calls this through a weak symbol; offline test binaries
// without this file resolve it to null and keep the cache enabled).
extern "C" int trt_settings_shader_cache_int() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.shader_cache ? 1 : 0;
}

// Consumed by bridge_vulkan through a weak symbol (same pattern as the int
// getter above): the bridge finds out where the persistent cache lives, and
// an offline test binary without this file simply gets no disk cache.
extern "C" const char* trt_settings_shader_cache_dir() {
  return g_shader_cache_dir.c_str();
}

// Texture quality tier, C linkage because bridge_d3d12 takes it as a weak
// symbol: an offline test binary without this file gets the default tier and
// therefore full quality, so descriptor assertions stay exact.
extern "C" int trt_settings_texture_quality_int() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.texture_quality;
}

int trt_settings_resolution_scale() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.resolution_scale;
}

int trt_settings_frame_rate_cap() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.frame_rate_cap;
}

int trt_settings_memory_budget_mb() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.memory_budget_mb;
}

bool trt_settings_fsb_decode() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.fsb_decode;
}

bool trt_settings_crash_report() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.crash_report;
}

bool trt_settings_vsync() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.vsync;
}

bool trt_settings_shader_cache() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.shader_cache;
}

int trt_settings_audio_buffer_ms() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.audio_buffer_ms;
}

int trt_settings_input_deadzone() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.input_deadzone;
}

int trt_settings_texture_quality() {
  std::lock_guard<std::mutex> lk(g_mu);
  return g_live.texture_quality;
}

} // namespace longan

// ---- C-linkage bridge surface --------------------------------------------
// The trt bridge layer resolves its settings hooks as weak `extern "C"`
// symbols (declared that way in bridge_sys.cpp, bridge_kernel32.cpp,
// input.cpp, bridge_msvcrt.cpp and bridge_wasapi.cpp). The getters above live
// in namespace longan, so they have C++ linkage: the linker never matched the
// bridges' C-linkage declarations, every one of those hooks stayed null, and
// the knob silently reported its built-in default instead of the value the
// user set. These forwarders provide the exact symbols the bridges ask for.
//
// Keep the signatures byte-identical to the bridge declarations; the linkage
// test (tests/test_settings_linkage.cpp) fails to link if one goes missing.
extern "C" {
void trt_settings_os(int* major, int* minor, int* build) {
  longan::trt_settings_os(major, minor, build);
}
bool trt_settings_write_watch() { return longan::trt_settings_write_watch(); }
bool trt_settings_pad_vibration() {
  return longan::trt_settings_pad_vibration();
}
int trt_settings_input_deadzone(void) {
  return longan::trt_settings_input_deadzone();
}
int trt_settings_memory_budget_mb(void) {
  return longan::trt_settings_memory_budget_mb();
}
int trt_settings_audio_buffer_ms() {
  return longan::trt_settings_audio_buffer_ms();
}
}  // extern "C"
