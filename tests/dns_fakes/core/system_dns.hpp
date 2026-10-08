#pragma once
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>
namespace clew::system_dns {
struct InterfaceDnsState {
    std::string adapter_guid;
    std::string friendly_name;
    bool automatic = true;
    std::vector<std::string> dns_servers;
};
namespace fake {
inline std::vector<InterfaceDnsState> interfaces;
inline std::map<std::string, std::vector<std::string>> current;
inline std::optional<std::vector<InterfaceDnsState>> backup;
inline std::set<std::string> set_failures;
inline std::set<std::string> restore_failures;
inline bool save_ok = true;
inline int sets = 0;
inline int restores = 0;
inline void reset() {
    interfaces = {{"eth", "Ethernet", true, {"192.168.50.1"}},
                  {"wifi", "Wi-Fi", false, {"10.1.2.1"}}};
    current.clear();
    for (const auto& st : interfaces) current[st.adapter_guid] = st.dns_servers;
    backup.reset(); set_failures.clear(); restore_failures.clear();
    save_ok = true; sets = 0; restores = 0;
}
}
inline std::vector<InterfaceDnsState> enumerate_active_interfaces() {
    auto states = fake::interfaces;
    for (auto& st : states) st.dns_servers = fake::current.at(st.adapter_guid);
    return states;
}
inline bool save_state(const std::filesystem::path&,
                       const std::vector<InterfaceDnsState>& states) {
    if (!fake::save_ok) return false;
    fake::backup = states;
    return true;
}
inline auto load_state(const std::filesystem::path&) { return fake::backup; }
inline void delete_state(const std::filesystem::path&) { fake::backup.reset(); }
inline bool set_interface_dns(const std::string& id,
                              const std::vector<std::string>& servers) {
    ++fake::sets;
    if (fake::set_failures.count(id)) return false;
    fake::current[id] = servers;
    return true;
}
inline bool restore_interface_dns(const InterfaceDnsState& st) {
    ++fake::restores;
    if (fake::restore_failures.count(st.adapter_guid)) return false;
    fake::current[st.adapter_guid] = st.dns_servers;
    return true;
}
}
