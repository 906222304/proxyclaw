// Actual shell service and file reader, confined to this test executable's dir.
#include "core/log_tail.hpp"
#include "core/exe_paths.hpp"
#include "services/shell_service.hpp"
#include <iostream>

static void require(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}
static void write(const std::filesystem::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
    require(bool(output), "fixture write failed");
}
int main() {
    try {
        auto log = clew::exe_relative("proxyclaw.log");
        std::filesystem::remove(log);
        require(!clew::shell_service::read_log()["exists"].get<bool>(), "missing file failed");
        write(log, "");
        auto empty = clew::read_log_tail(log);
        require(empty.exists && empty.text.empty() && !empty.truncated, "empty file failed");
        write(log, "first\r\nsecond\r\nthird\r\n");
        auto tail = clew::read_log_tail(log, 256, 2);
        require(tail.text == "second\r\nthird\r\n" && tail.truncated, "line limit failed");
        write(log, "first\nsecond\nthird");
        require(clew::read_log_tail(log, 256, 2).text == "second\nthird", "partial final line failed");
        auto folder = clew::exe_directory() / L"log-tail-中文测试";
        std::filesystem::create_directories(folder);
        auto unicode = folder / L"日志.txt";
        write(unicode, "连接正常\n断线记录\n");
        require(clew::read_log_tail(unicode).text == "连接正常\n断线记录\n", "Unicode path/text failed");
        write(log, std::string(300'000, 'x'));
        auto huge = clew::read_log_tail(log);
        require(huge.text.size() == 256 * 1024 && huge.truncated, "byte bound/long line failed");
        std::string many;
        for (int i = 0; i < 1100; ++i) many += std::to_string(i) + "\n";
        write(log, many);
        auto snapshot = clew::shell_service::read_log();
        auto text = snapshot["text"].get<std::string>();
        require(text.starts_with("100\n") && text.ends_with("1099\n"), "fixed service line bound failed");
        require(snapshot["path"].get<std::string>() == log.string(), "service read outside own directory");
        write(log, "partial UTF-8: \xe4\xb8");
        auto encoded = clew::shell_service::read_log().dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        require(nlohmann::json::parse(encoded)["text"].get<std::string>().starts_with("partial UTF-8:"), "partial UTF-8 serialization failed");
        auto rotated = clew::exe_relative("proxyclaw.previous.log");
        std::filesystem::remove(rotated);
        std::filesystem::rename(log, rotated);
        write(log, "new after rotation\n");
        require(clew::shell_service::read_log()["text"] == "new after rotation\n", "rotation selected stale file");
        std::cout << "PASS log tail: missing/empty, CRLF/partial line, Unicode, byte/line bounds, UTF-8 fragment, rotation, fixed service path" << std::endl;
    } catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
