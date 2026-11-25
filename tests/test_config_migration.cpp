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

        // v0.15 #2: config import via set_raw_config applies versioned migration
        // (v1 -> v2, proxy_groups population, next_group_id normalization) and
        // rejects unsupported versions without clobbering live config.
        const auto dir_b = root / "fresh-dir";
        fs::create_directories(dir_b);
        const auto imported_cfg = dir_b / "proxyclaw.json";
        fs::remove(imported_cfg);
        clew::config_manager target(imported_cfg);
        check(target.load(), "fresh directory initializes default config");

        const std::string v1_json = R"({
            "version": 1,
            "default_proxy": {"type": "socks5", "host": "127.0.0.1", "port": 10808},
            "auto_rules": [
                {
                    "id": "r_v1",
                    "name": "Curl",
                    "enabled": true,
                    "process_name": "curl.exe",
                    "proxy": {"type": "socks5", "host": "127.0.0.1", "port": 10809}
                }
            ]
        })";
        check(target.set_raw_config(v1_json).empty(), "v1 config import migrates cleanly");
        check(target.get_v2().version == 2, "migrated version is 2");
        check(target.get_v2().proxy_groups.size() == 2, "v1 import populates default + inline rule group");
        check(target.get_v2().auto_rules.size() == 1 && target.get_v2().auto_rules[0].proxy_group_id == 1,
              "v1 rule binds to migrated proxy group");
        check(target.get_v2().next_group_id == 2, "next_group_id normalized above max id");

        const std::string bad_ver = R"({"version": 99})";
        check(!target.set_raw_config(bad_ver).empty(), "unsupported future version is rejected");
        check(target.get_v2().auto_rules.size() == 1, "rejected import leaves existing config intact");

        // Exported v2 config imported into another fresh directory reloads identically.
        const std::string exported = target.get_raw_config();
        const auto dir_c = root / "second-dir";
        fs::create_directories(dir_c);
        const auto cloned_cfg = dir_c / "proxyclaw.json";
        fs::remove(cloned_cfg);
        clew::config_manager clone(cloned_cfg);
        check(clone.load() && clone.set_raw_config(exported).empty(),
              "exported v2 config imports into fresh directory");
        clew::config_manager reloaded(cloned_cfg);
        check(reloaded.load()
              && reloaded.get_v2().proxy_groups.size() == 2
              && reloaded.get_v2().auto_rules.size() == 1
              && reloaded.get_v2().auto_rules[0].id == "r_v1",
              "imported config persists and reloads identically in new directory");

        for (const auto& file : {legacy, current, custom, imported_cfg, cloned_cfg}) fs::remove(file);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
