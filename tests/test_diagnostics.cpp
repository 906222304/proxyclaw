// Unit tests for v0.18 #4 diagnostic bundle sanitization and PKZIP archive writer.
// Pure C++23, no driver / admin rights required.
// Optional CLI: --write-sample <path.zip> writes a sample bundle for external verification.

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "core/diagnostics.hpp"

using namespace clew;

namespace {

int failures = 0;

void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cerr << "FAIL: " << what << "\n";
    }
}

uint16_t rd16(const std::string& s, std::size_t off) {
    return static_cast<uint16_t>(
        static_cast<uint8_t>(s[off]) |
        (static_cast<uint16_t>(static_cast<uint8_t>(s[off + 1])) << 8));
}

uint32_t rd32(const std::string& s, std::size_t off) {
    return static_cast<uint32_t>(static_cast<uint8_t>(s[off])) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[off + 1])) << 8) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[off + 2])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(s[off + 3])) << 24);
}

void crc32_known_vector() {
    // Standard IEEE 802.3 CRC-32 check value for ASCII "123456789".
    check(crc32_ieee("123456789") == 0xCBF43926u, "CRC-32 standard vector matches");
    check(crc32_ieee("") == 0x00000000u, "CRC-32 empty string is 0");
}

void config_redaction_strips_all_secrets() {
    nlohmann::json cfg = {
        {"version", 2},
        {"default_proxy", {
            {"host", "127.0.0.1"},
            {"port", 7890},
            {"user", "alice"},
            {"password", "SuperSecretDefaultPass!"},
        }},
        {"proxy_groups", nlohmann::json::array({
            {{"id", 0}, {"name", "Default"}, {"host", "127.0.0.1"}, {"port", 1080}, {"user", ""}, {"password", ""}},
            {{"id", 1}, {"name", "Corp"}, {"host", "proxy.corp"}, {"port", 1081}, {"user", "bob"}, {"password", "CorpPass99"}},
        })},
        {"custom_meta", {
            {"api_key", "key-xyz"},
            {"Token", "tok-abc"},
            {"proxy_url", "socks5://carol:UrlPass88@10.0.0.1:1080/path"},
        }},
    };

    const auto out = sanitize_config_for_diagnostics(cfg);
    check(out["default_proxy"]["user"] == "alice", "username preserved");
    check(out["default_proxy"]["password"] == "[REDACTED]", "default_proxy password redacted");
    check(out["proxy_groups"][0]["password"] == "", "empty password stays empty");
    check(out["proxy_groups"][1]["password"] == "[REDACTED]", "group password redacted");
    check(out["custom_meta"]["api_key"] == "[REDACTED]", "api_key redacted");
    check(out["custom_meta"]["Token"] == "[REDACTED]", "case-insensitive token redacted");
    check(out["custom_meta"]["proxy_url"] == "socks5://carol:[REDACTED]@10.0.0.1:1080/path",
          "embedded URL password redacted");

    const std::string dumped = out.dump();
    check(dumped.find("SuperSecretDefaultPass!") == std::string::npos, "default password absent");
    check(dumped.find("CorpPass99") == std::string::npos, "group password absent");
    check(dumped.find("UrlPass88") == std::string::npos, "URL password absent");
    check(dumped.find("key-xyz") == std::string::npos, "api_key absent");
    check(dumped.find("tok-abc") == std::string::npos, "token absent");
}

void env_and_log_redaction() {
    nlohmann::json env = {
        {"HTTP_PROXY", "http://user1:EnvPass1@127.0.0.1:8080"},
        {"HTTPS_PROXY", "https://127.0.0.1:8080"},
        {"NO_PROXY", "localhost,127.0.0.1"},
    };
    const auto clean_env = sanitize_env_for_diagnostics(env);
    check(clean_env["HTTP_PROXY"] == "http://user1:[REDACTED]@127.0.0.1:8080", "HTTP_PROXY redacted");
    check(clean_env["HTTPS_PROXY"] == "https://127.0.0.1:8080", "credential-less URL unchanged");

    const std::string log =
        "2026-11-26 12:00:00 [I] Open http://127.0.0.1:18080/api/session?token=deadbeef1234\n"
        "2026-11-26 12:00:01 [I] Header X-ProxyClaw-Token: MyHeaderToken99\n"
        "2026-11-26 12:00:02 [I] Header X-ProxyClaw-Token: \n"
        "2026-11-26 12:00:03 [I] Upstream socks5://admin:LogSecret77@1.2.3.4:1080\n";
    const std::string clean_log = sanitize_log_text(log);
    check(clean_log.find("deadbeef1234") == std::string::npos, "query token redacted");
    check(clean_log.find("MyHeaderToken99") == std::string::npos, "header token redacted");
    check(clean_log.find("LogSecret77") == std::string::npos, "log URL password redacted");
    check(clean_log.find("token=[REDACTED]") != std::string::npos, "token placeholder present");
    check(clean_log.find("X-ProxyClaw-Token: [REDACTED]\n") != std::string::npos, "header placeholder present");
    check(clean_log.find("X-ProxyClaw-Token: \n") != std::string::npos, "empty header value untouched");
}

diagnostics_bundle_input make_sample_input() {
    diagnostics_bundle_input in;
    in.version = "0.18.0-test";
    in.timestamp_utc = 1795651200;  // 2026-11-26T00:00:00Z
    in.os_info = "Windows 10.0.22631 (x64)";
    in.stats = {
        {"tree_ready", true},
        {"process_count", 150},
        {"hijacked_pids", 3},
    };
    in.env = {
        {"HTTP_PROXY", "http://dev:EnvSecret42@127.0.0.1:7890"},
        {"NO_PROXY", "localhost"},
    };
    in.raw_config = {
        {"version", 2},
        {"proxy_groups", nlohmann::json::array({
            {{"id", 0}, {"name", "Main"}, {"host", "127.0.0.1"}, {"port", 1080},
             {"user", "u"}, {"password", "TopSecretSocks5Pass"}},
        })},
    };
    in.log_exists = true;
    in.log_truncated = false;
    in.log_text = "2026-11-26 00:00:00 [I] Ready token=SecretSessionToken\n";
    return in;
}

void zip_structure_and_sanitization() {
    const auto in = make_sample_input();
    const std::string zip = build_diagnostics_zip(in);

    check(zip.size() > 64, "zip is non-empty");
    check(rd32(zip, 0) == 0x04034B50u, "starts with local file header signature");
    const std::size_t eocd = zip.size() - 22;
    check(rd32(zip, eocd) == 0x06054B50u, "ends with EOCD signature");
    check(rd16(zip, eocd + 8) == 3 && rd16(zip, eocd + 10) == 3, "exactly 3 archive entries");

    // Walk all 3 local entries and verify names + CRC-32.
    std::size_t off = 0;
    const std::string expected_names[3] = {"summary.json", "config.sanitized.json", "proxyclaw.log"};
    for (int i = 0; i < 3; ++i) {
        check(rd32(zip, off) == 0x04034B50u, "local header signature");
        const uint32_t crc = rd32(zip, off + 14);
        const uint32_t comp_sz = rd32(zip, off + 18);
        const uint32_t uncomp_sz = rd32(zip, off + 22);
        const uint16_t name_len = rd16(zip, off + 26);
        const uint16_t extra_len = rd16(zip, off + 28);
        check(comp_sz == uncomp_sz, "STORE mode sizes match");
        const std::string name = zip.substr(off + 30, name_len);
        const std::string body = zip.substr(off + 30 + name_len + extra_len, comp_sz);
        check(name == expected_names[i], "entry name matches: " + name);
        check(crc32_ieee(body) == crc, "entry CRC-32 verifies: " + name);
        off += 30 + name_len + extra_len + comp_sz;
    }

    // Secrets must NEVER appear anywhere in raw ZIP bytes.
    check(zip.find("TopSecretSocks5Pass") == std::string::npos, "SOCKS5 password absent from zip");
    check(zip.find("EnvSecret42") == std::string::npos, "env proxy password absent from zip");
    check(zip.find("SecretSessionToken") == std::string::npos, "log token absent from zip");
    check(zip.find("[REDACTED]") != std::string::npos, "redacted marker present in zip");

    const std::string fn = format_diagnostics_filename(in.timestamp_utc);
    check(fn.starts_with("proxyclaw-diagnostics-") && fn.ends_with(".zip"), "filename format valid");
}

} // namespace

int main(int argc, char** argv) {
    crc32_known_vector();
    config_redaction_strips_all_secrets();
    env_and_log_redaction();
    zip_structure_and_sanitization();

    if (argc == 3 && std::string_view(argv[1]) == "--write-sample") {
        const std::string zip = build_diagnostics_zip(make_sample_input());
        std::ofstream out(argv[2], std::ios::binary);
        out.write(zip.data(), static_cast<std::streamsize>(zip.size()));
    }

    if (failures) {
        std::cerr << "diagnostics_tests: " << failures << " failure(s)\n";
        return 1;
    }
    std::cout << "diagnostics_tests: all passed\n";
    return 0;
}
