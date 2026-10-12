#pragma once

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace clew {

struct LogTail {
    std::string text;
    bool exists{};
    bool truncated{};
};

// Seek from the end rather than loading a potentially 50 MB active log.
// Reopen on each snapshot so rotation automatically selects the new file.
inline LogTail read_log_tail(const std::filesystem::path& path,
                             size_t max_bytes = 256 * 1024, size_t max_lines = 1000) {
    LogTail result;
    std::error_code ec;
    result.exists = std::filesystem::exists(path, ec);
    if (ec) throw std::runtime_error("Cannot inspect log file");
    if (!result.exists) return result;
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("Cannot open log file");
    auto size = input.tellg();
    if (size < 0) throw std::runtime_error("Cannot measure log file");
    if (!max_bytes || !max_lines) { result.truncated = size > 0; return result; }
    auto count = std::min<std::streamoff>(size, static_cast<std::streamoff>(max_bytes));
    input.seekg(size - count);
    result.text.resize(static_cast<size_t>(count));
    input.read(result.text.data(), count);
    if (input.bad()) throw std::runtime_error("Cannot read log file");
    result.text.resize(static_cast<size_t>(input.gcount()));
    result.truncated = size > count;
    if (result.truncated) {
        // Skip a partial first line, but retain the tail of a single huge line.
        auto end = result.text.find('\n');
        if (end != std::string::npos && end + 1 < result.text.size())
            result.text.erase(0, end + 1);
    }
    auto cursor = result.text.size();
    if (cursor && result.text.back() == '\n') --cursor;
    for (size_t line = 0; line < max_lines && cursor; ++line) {
        auto previous = result.text.rfind('\n', cursor - 1);
        if (previous == std::string::npos) break;
        if (line + 1 == max_lines) {
            result.text.erase(0, previous + 1);
            result.truncated = true;
            break;
        }
        cursor = previous;
    }
    return result;
}

} // namespace clew
