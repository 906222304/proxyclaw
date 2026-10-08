// Real config parsing/persistence; logging is replaced by network_fakes.
// No real proxy configuration, system DNS, or Windows startup task is touched.
#include "config/config_manager.hpp"
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace fs = std::filesystem;
static void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
    std::cout << "PASS " << message << '\n';
}
static std::string read(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{file}, std::istreambuf_iterator<char>{}};
}
static void write(const fs::path& path, std::string_view text) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << text;
    if (!file) throw std::runtime_error("fixture write failed");
}
int main() {
    try {
        // Fixed, workspace-local fixture files. Each case rewrites its inputs.
        const auto root = fs::current_path() / "build" / "config-migration-tests";
        fs::create_directories(root);
        const auto legacy = root / "clew.json";
        const auto current = root / "proxyclaw.json";
        fs::remove(current);
        fs::remove(legacy);
        clew::config_manager fresh(current);
        check(fresh.load() && fs::exists(current), "fresh launch creates new configuration name");

        clew::ConfigV2 old;
        old.default_proxy.port = 7890;
        old.ui.close_to_tray = false;
        old.dns.enabled = false;
        old.dns.upstream_host = "1.1.1.1";
        const auto bytes = nlohmann::json(old).dump(2);
        write(legacy, bytes);
        fs::remove(current);
        clew::config_manager imported(current);
        check(imported.load() && imported.get_v2().default_proxy.port == 7890 &&
              !imported.get_v2().ui.close_to_tray && !imported.get_v2().dns.enabled &&
              imported.get_v2().dns.upstream_host == "1.1.1.1",
              "legacy proxy and explicit UI/DNS preferences are preserved");
        check(fs::exists(current) && read(legacy) == bytes,
              "migration writes new file without changing original bytes");
        imported.get_v2().default_proxy.port = 1080;
        check(imported.save() && read(legacy) == bytes,
              "subsequent saves leave the upstream configuration intact");
        clew::config_manager preferred(current);
        check(preferred.load() && preferred.get_v2().default_proxy.port == 1080,
              "existing new configuration takes precedence over legacy");
        const auto custom = root / "custom.json";
        fs::remove(custom);
        clew::config_manager explicit_path(custom);
        check(explicit_path.load() && explicit_path.get_v2().dns.upstream_host == "8.8.8.8",
              "custom configuration names do not import a legacy sibling");
        fs::remove(current);
        write(legacy, "{malformed json");
        clew::config_manager malformed(current);
        check(!malformed.load() && !fs::exists(current),
              "invalid legacy data is rejected without persisting defaults");
        for (const auto& file : {legacy, current, custom}) fs::remove(file);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
