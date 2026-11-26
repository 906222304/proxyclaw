#pragma once

// Pure C++23 diagnostic bundle sanitization & ZIP assembly (v0.18 #4).
//
// Redacts SOCKS5 passwords, URL userinfo credentials, and API/session tokens
// before packing summary.json, config.sanitized.json, and proxyclaw.log into
// a standard ZIP archive. No OS dependencies so it can be unit-tested on any
// platform.

#include <cctype>
#include <cstddef>
#include <cstdio>
#include <ctime>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "core/mini_zip.hpp"

namespace clew {

inline constexpr std::string_view kDiagnosticsRedacted = "[REDACTED]";

namespace diagnostics_detail {

inline std::string ascii_lower(std::string_view s) {
    std::string out(s.size(), '\0');
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
    }
    return out;
}

inline bool is_sensitive_key(std::string_view key) {
    const std::string k = ascii_lower(key);
    return k == "password" || k == "passwd" || k == "secret" || k == "token" ||
           k == "api_key" || k == "apikey" || k == "authorization" ||
           k == "auth_token" || k == "proxy_password" || k == "access_token";
}

inline bool is_url_boundary(char c) noexcept {
    const unsigned char u = static_cast<unsigned char>(c);
    return std::isspace(u) != 0 || c == '/' || c == '?' || c == '#' ||
           c == '"' || c == '\'' || c == '<' || c == '>' || c == ',' || c == ';';
}

inline bool is_token_char(char c) noexcept {
    const unsigned char u = static_cast<unsigned char>(c);
    return std::isalnum(u) != 0 || c == '-' || c == '_' || c == '.' || c == '+' || c == '=' || c == '/';
}

} // namespace diagnostics_detail

// Redact credentials embedded in URLs (e.g. "http://user:pass@host:8080" ->
// "http://user:[REDACTED]@host:8080", or "socks5://secret@host" ->
// "socks5://[REDACTED]@host").
inline std::string redact_url_credentials(std::string_view input) {
    std::string out;
    out.reserve(input.size());
    std::size_t pos = 0;
    while (pos < input.size()) {
        const std::size_t scheme = input.find("://", pos);
        if (scheme == std::string_view::npos) {
            out.append(input.substr(pos));
            break;
        }
        const std::size_t auth_start = scheme + 3;
        out.append(input.substr(pos, auth_start - pos));

        // Scan authority up to first delimiter.
        std::size_t end = auth_start;
        std::size_t at_pos = std::string_view::npos;
        while (end < input.size() && !diagnostics_detail::is_url_boundary(input[end])) {
            if (input[end] == '@') at_pos = end;
            ++end;
        }

        if (at_pos != std::string_view::npos && at_pos > auth_start) {
            const std::string_view userinfo = input.substr(auth_start, at_pos - auth_start);
            const std::size_t colon = userinfo.find(':');
            if (colon != std::string_view::npos) {
                out.append(userinfo.substr(0, colon + 1));
                out.append(kDiagnosticsRedacted);
            } else {
                out.append(kDiagnosticsRedacted);
            }
            out.push_back('@');
            out.append(input.substr(at_pos + 1, end - (at_pos + 1)));
        } else {
            out.append(input.substr(auth_start, end - auth_start));
        }
        pos = end;
    }
    return out;
}

// Recursively redact passwords / secrets / tokens and credentialed URLs from a
// ProxyClaw config JSON tree. Empty strings stay empty so diagnostics still
// show whether authentication was configured.
inline nlohmann::json sanitize_config_for_diagnostics(nlohmann::json value) {
    if (value.is_object()) {
        for (auto& [key, val] : value.items()) {
            if (diagnostics_detail::is_sensitive_key(key)) {
                if (val.is_string()) {
                    if (!val.get_ref<const std::string&>().empty()) {
                        val = std::string(kDiagnosticsRedacted);
                    }
                } else if (!val.is_null()) {
                    val = std::string(kDiagnosticsRedacted);
                }
            } else {
                val = sanitize_config_for_diagnostics(std::move(val));
            }
        }
        return value;
    }
    if (value.is_array()) {
        for (auto& item : value) {
            item = sanitize_config_for_diagnostics(std::move(item));
        }
        return value;
    }
    if (value.is_string()) {
        const auto& s = value.get_ref<const std::string&>();
        if (s.find("://") != std::string::npos && s.find('@') != std::string::npos) {
            value = redact_url_credentials(s);
        }
    }
    return value;
}

// Redact proxy URL credentials from environment variable snapshot.
inline nlohmann::json sanitize_env_for_diagnostics(nlohmann::json env) {
    if (!env.is_object()) return env;
    for (auto& [key, val] : env.items()) {
        (void)key;
        if (val.is_string()) {
            val = redact_url_credentials(val.get_ref<const std::string&>());
        }
    }
    return env;
}

// Redact session tokens, auth headers, and URL credentials from log lines.
inline std::string sanitize_log_text(std::string_view input) {
    std::string text = redact_url_credentials(input);

    auto redact_after_prefix = [&](std::string_view prefix_lower, bool to_eol) {
        std::string lower = diagnostics_detail::ascii_lower(text);
        std::string out;
        out.reserve(text.size());
        std::size_t pos = 0;
        while (pos < text.size()) {
            const std::size_t hit = lower.find(prefix_lower, pos);
            if (hit == std::string::npos) {
                out.append(text.data() + pos, text.size() - pos);
                break;
            }
            const std::size_t val_start = hit + prefix_lower.size();
            out.append(text.data() + pos, val_start - pos);
            std::size_t val_end = val_start;
            std::size_t secret_start = val_start;
            if (to_eol) {
                while (val_end < text.size() && text[val_end] == ' ') {
                    out.push_back(text[val_end++]);
                }
                secret_start = val_end;
                while (val_end < text.size() && text[val_end] != '\r' && text[val_end] != '\n') {
                    ++val_end;
                }
            } else {
                while (val_end < text.size() && diagnostics_detail::is_token_char(text[val_end])) {
                    ++val_end;
                }
            }
            if (val_end > secret_start) {
                out.append(kDiagnosticsRedacted);
            }
            pos = val_end;
        }
        text = std::move(out);
    };

    redact_after_prefix("token=", false);
    redact_after_prefix("password=", false);
    redact_after_prefix("x-proxyclaw-token:", true);
    redact_after_prefix("authorization:", true);
    return text;
}

inline std::string format_utc_iso8601(std::time_t ts) {
    std::tm utc{};
#ifdef _WIN32
    if (gmtime_s(&utc, &ts) != 0) return "1970-01-01T00:00:00Z";
#else
    if (!gmtime_r(&ts, &utc)) return "1970-01-01T00:00:00Z";
#endif
    char buf[32]{};
    const std::size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return n > 0 ? std::string(buf, n) : std::string("1970-01-01T00:00:00Z");
}

inline std::string format_diagnostics_filename(std::time_t ts) {
    std::tm utc{};
#ifdef _WIN32
    if (gmtime_s(&utc, &ts) != 0) return "proxyclaw-diagnostics.zip";
#else
    if (!gmtime_r(&ts, &utc)) return "proxyclaw-diagnostics.zip";
#endif
    char buf[64]{};
    const std::size_t n = std::strftime(buf, sizeof(buf), "proxyclaw-diagnostics-%Y%m%d-%H%M%S.zip", &utc);
    return n > 0 ? std::string(buf, n) : std::string("proxyclaw-diagnostics.zip");
}

struct diagnostics_bundle_input {
    std::string    version;
    std::time_t    timestamp_utc{0};
    std::string    os_info;
    nlohmann::json stats;
    nlohmann::json env;
    nlohmann::json raw_config;
    std::string    log_text;
    bool           log_exists{false};
    bool           log_truncated{false};
};

inline std::string build_diagnostics_zip(const diagnostics_bundle_input& in) {
    const std::time_t ts = in.timestamp_utc ? in.timestamp_utc : std::time(nullptr);
    const nlohmann::json sanitized_cfg = sanitize_config_for_diagnostics(in.raw_config);
    const nlohmann::json sanitized_env = sanitize_env_for_diagnostics(in.env);
    std::string sanitized_log = sanitize_log_text(in.log_text);
    if (!in.log_exists && sanitized_log.empty()) {
        sanitized_log = "# proxyclaw.log does not exist yet.\n";
    }

    nlohmann::json summary;
    summary["schema_version"]   = 1;
    summary["version"]          = in.version;
    summary["generated_at_utc"] = format_utc_iso8601(ts);
    if (!in.os_info.empty()) summary["os"] = in.os_info;
    summary["log"] = {
        {"exists",    in.log_exists},
        {"truncated", in.log_truncated},
        {"bytes",     sanitized_log.size()},
    };
    summary["env"]   = sanitized_env;
    summary["stats"] = in.stats;

    std::string summary_text = summary.dump(2) + "\n";
    std::string config_text  = sanitized_cfg.dump(2) + "\n";

    mini_zip_writer zip(ts);
    zip.add_file("summary.json", summary_text);
    zip.add_file("config.sanitized.json", config_text);
    zip.add_file("proxyclaw.log", sanitized_log);
    return zip.finish();
}

} // namespace clew
