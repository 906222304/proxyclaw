// Hook mode control pipe server tests (src/hook/hook_pipe_server.hpp):
// verifies normal CallNamedPipeW round-trips, bounded timeout on stalled
// clients that never read their reply, and prompt stop() cancellation.
#include "hook/hook_pipe_server.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using namespace std::chrono_literals;
using clew::hook::kMagic;
using clew::hook::kVersion;
using clew::hook::msg_type;
using clew::hook::pipe_server;
using clew::hook::reply;
using clew::hook::request;
using clew::hook::verdict;

#define CHECK(expr) do { if (!(expr)) throw std::runtime_error(#expr); } while (false)

namespace {

std::wstring unique_pipe(const wchar_t* tag) {
    return L"\\\\.\\pipe\\proxyclaw-hook-test-" + std::to_wstring(GetCurrentProcessId()) + L"-" + tag;
}

request make_req(uint16_t src_port) {
    request req{};
    req.magic    = kMagic;
    req.version  = kVersion;
    req.type     = static_cast<uint32_t>(msg_type::connect);
    req.family   = 4;
    req.src_port = src_port;
    req.dst_port = 80;
    req.dst[0]   = 1;
    req.dst[1]   = 1;
    req.dst[2]   = 1;
    req.dst[3]   = 1;
    return req;
}

reply echo_handler(const request& req, DWORD client_pid) {
    reply rep{};
    rep.magic      = kMagic;
    rep.verdict    = static_cast<uint32_t>(client_pid == GetCurrentProcessId() ? verdict::proxy : verdict::direct);
    rep.relay_port = req.src_port;
    return rep;
}

HANDLE open_stalled_client(const std::wstring& name, uint16_t src_port) {
    HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    CHECK(h != INVALID_HANDLE_VALUE);
    const request req = make_req(src_port);
    DWORD written = 0;
    const BOOL ok = WriteFile(h, &req, sizeof(req), &written, nullptr);
    CHECK(ok && written == sizeof(req));
    // Intentionally do NOT read the reply and keep the handle open.
    return h;
}

void round_trip_calls() {
    const std::wstring name = unique_pipe(L"roundtrip");
    pipe_server srv(&echo_handler, name, 500);
    CHECK(srv.start(2));
    for (uint16_t i = 1; i <= 100; ++i) {
        request req = make_req(static_cast<uint16_t>(40000 + i));
        reply rep{};
        DWORD got = 0;
        const BOOL ok = CallNamedPipeW(name.c_str(), &req, sizeof(req), &rep, sizeof(rep), &got, 2000);
        CHECK(ok && got == sizeof(rep));
        CHECK(rep.magic == kMagic);
        CHECK(static_cast<verdict>(rep.verdict) == verdict::proxy);
        CHECK(rep.relay_port == static_cast<uint16_t>(40000 + i));
    }
    CHECK(srv.requests() == 100);
    CHECK(srv.rejected() == 0);
    srv.stop();
}

void stalled_client_times_out_and_releases_worker() {
    const std::wstring name = unique_pipe(L"stalled");
    pipe_server srv(&echo_handler, name, 200);
    // Single worker thread: if the stalled client pinned it (as blocking
    // FlushFileBuffers did), the second client below would time out forever.
    CHECK(srv.start(1));
    HANDLE stalled = open_stalled_client(name, 41001);

    request req = make_req(41002);
    reply rep{};
    DWORD got = 0;
    const auto t0 = std::chrono::steady_clock::now();
    const BOOL ok = CallNamedPipeW(name.c_str(), &req, sizeof(req), &rep, sizeof(rep), &got, 3000);
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CloseHandle(stalled);
    srv.stop();

    CHECK(ok && got == sizeof(rep));
    CHECK(rep.relay_port == 41002);
    CHECK(elapsed < 2500ms);
}

void stop_cancels_stalled_drain_promptly() {
    const std::wstring name = unique_pipe(L"stop");
    // Long I/O timeout so stop() must actively cancel the drain wait rather
    // than waiting for the timeout to expire.
    pipe_server srv(&echo_handler, name, 5000);
    CHECK(srv.start(2));

    HANDLE c1 = open_stalled_client(name, 42001);
    HANDLE c2 = open_stalled_client(name, 42002);

    const auto deadline = std::chrono::steady_clock::now() + 2s;
    while (srv.requests() < 2 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
    CHECK(srv.requests() == 2);
    // Let both workers advance from handler_() + WriteFile() into the EOF wait.
    std::this_thread::sleep_for(50ms);

    const auto t0 = std::chrono::steady_clock::now();
    srv.stop();
    const auto elapsed = std::chrono::steady_clock::now() - t0;

    CloseHandle(c1);
    CloseHandle(c2);
    CHECK(elapsed < 1500ms);
}

} // namespace

int main() {
    const std::pair<const char*, void(*)()> cases[] = {
        {"100 CallNamedPipeW round-trips succeed without dropped replies", round_trip_calls},
        {"stalled client times out and frees the pipe worker", stalled_client_times_out_and_releases_worker},
        {"stop() cancels stalled drain waits promptly", stop_cancels_stalled_drain_promptly},
    };
    int failures = 0;
    for (const auto& [name, test] : cases) {
        try { test(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& e) {
            ++failures;
            std::cerr << "FAIL " << name << ": " << e.what() << '\n';
        }
    }
    return failures ? 1 : 0;
}
