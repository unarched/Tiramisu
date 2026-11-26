#include "steam_install.h"

#include "../trt/engine_synthesizer.h"
#include "../trt/steam_library.h"

#include <filesystem>
#include <fstream>
#include <utility>

namespace longan {

steam_local_install inspect_steam_install(const std::string& game_dir) {
  namespace fs = std::filesystem;
  steam_local_install local;
  if (game_dir.empty()) return local;
  const auto metadata = fs::path(game_dir) / ".tiramisu";
  const auto pending_path = metadata / "steam-install-pending";
  const auto launch_path = metadata / "steam-launch-exe.txt";
  local.app_id = trt_steam_read_appid(game_dir.c_str());

  std::error_code ec;
  if (fs::exists(pending_path, ec) || ec) {
    if (!local.app_id) std::ifstream(pending_path) >> local.app_id;
    local.state = steam_install_state::incomplete;
    return local;
  }
  if (!local.app_id) return local;

  local.state = steam_install_state::missing_executable;
  std::string launch;
  const bool has_launch_file = fs::exists(launch_path, ec);
  if (ec) return local;
  if (has_launch_file) {
    std::ifstream file(launch_path, std::ios::binary);
    char buffer[1024]{};
    if (!file.getline(buffer, sizeof(buffer))) return local;
    launch.assign(buffer, static_cast<size_t>(file.gcount()) - (file.eof() ? 0 : 1));
    if (!launch.empty() && launch.back() == '\r') launch.pop_back();
    if (!trt_steam_normalize_content_path(launch, &launch)) return local;
  }
  if (trt_find_guest_executable(game_dir.c_str(), has_launch_file ? launch.c_str() : nullptr,
                                &local.executable)) {
    std::string normalized;
    if (trt_steam_normalize_content_path(local.executable, &normalized)) {
      local.executable = std::move(normalized);
      local.state = steam_install_state::ready;
    }
  }
  return local;
}

}  // namespace longan
