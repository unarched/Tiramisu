#ifndef TIRAMISU_HOST_STEAM_INSTALL_H
#define TIRAMISU_HOST_STEAM_INSTALL_H

#include <cstdint>
#include <string>

namespace longan {

enum class steam_install_state { unrelated, incomplete, missing_executable, ready };

struct steam_local_install {
  uint32_t app_id = 0;
  steam_install_state state = steam_install_state::unrelated;
  std::string executable;
};

// The shelf and Steam tab share this read-only check. A published Steam
// launch path is authoritative. Legacy installs can use normal PE discovery.
steam_local_install inspect_steam_install(const std::string& game_dir);

}  // namespace longan

#endif
