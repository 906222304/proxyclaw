#pragma once

// Hook mode control pipe (\\.\pipe\proxyclaw-hook-v1): one fixed-size
// request, one fixed-size reply per connection (the DLL uses CallNamedPipeW).
//
// A few worker threads each own one overlapped pipe instance and loop
// connect -> read -> answer -> disconnect. Overlapped I/O only so stop() can
// interrupt a waiting ConnectNamedPipe; nothing here touches an IOCP.
//
// The answer is produced by the handler with the client's PID as the kernel
// reports it (GetNamedPipeClientProcessId), never the PID a client claims.
//
// Access: SYSTEM and Administrators full; everyone, AppContainers and
// low-integrity clients may read/write (an injected process can run at any
// of those). Remote clients are rejected.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <windows.h>
#include <sddl.h>

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "core/log.hpp"
#include "hook/hook_protocol.hpp"

namespace clew::hook {

class pipe_server {
public:
    using handler = std::function<reply(const request&, DWORD client_pid)>;
    static constexpr DWORD kDefaultIoTimeoutMs = 1000;

    explicit pipe_server(handler h, std::wstring pipe_name = kPipeName,
                         DWORD io_timeout_ms = kDefaultIoTimeoutMs)
        : handler_(std::move(h)), pipe_name_(std::move(pipe_name)),
          io_timeout_ms_(io_timeout_ms) {}
    ~pipe_server() { stop(); }

    pipe_server(const pipe_server&) = delete;
    pipe_server& operator=(const pipe_server&) = delete;

    bool start(int threads = 4) {
        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stop_event_) return false;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;WD)(A;;GRGW;;;AC)S:(ML;;NW;;;LW)",
                SDDL_REVISION_1, &sd_, nullptr)) {
            PC_LOG_ERROR("[HOOK-PIPE] security descriptor failed: {}", GetLastError());
            return false;
        }
        // The first instance claims the name; a second ProxyClaw (or anything
        // squatting on it) makes start fail instead of sharing the pipe.
        HANDLE first = create_instance(true);
        if (first == INVALID_HANDLE_VALUE) {
            PC_LOG_ERROR("[HOOK-PIPE] cannot create {}: {}", "proxyclaw-hook-v1", GetLastError());
            return false;
        }
        running_ = true;
        threads_.emplace_back([this, first] { serve(first); });
        for (int i = 1; i < threads; ++i) {
            HANDLE h = create_instance(false);
            if (h == INVALID_HANDLE_VALUE) break;
            threads_.emplace_back([this, h] { serve(h); });
        }
        PC_LOG_INFO("[HOOK-PIPE] listening ({} instances)", threads_.size());
        return true;
    }

    void stop() {
        if (!running_.exchange(false)) {
            cleanup();
            return;
        }
        SetEvent(stop_event_);
        for (auto& t : threads_) if (t.joinable()) t.join();
        threads_.clear();
        cleanup();
    }

    uint64_t requests() const { return requests_.load(); }
    uint64_t rejected() const { return rejected_.load(); }

private:
    HANDLE create_instance(bool first) {
        SECURITY_ATTRIBUTES sa{sizeof(sa), sd_, FALSE};
        return CreateNamedPipeW(pipe_name_.c_str(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | (first ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES, sizeof(reply), sizeof(request), 0, &sa);
    }

    // Wait for one overlapped operation, or for stop. False on stop, error or
    // timeout (the operation is cancelled before returning).
    bool wait_io(HANDLE pipe, OVERLAPPED& ov, DWORD timeout_ms, DWORD& bytes) {
        HANDLE events[2] = {ov.hEvent, stop_event_};
        const DWORD w = WaitForMultipleObjects(2, events, FALSE, timeout_ms);
        if (w != WAIT_OBJECT_0) {
            CancelIoEx(pipe, &ov);
            GetOverlappedResult(pipe, &ov, &bytes, TRUE);
            return false;
        }
        return GetOverlappedResult(pipe, &ov, &bytes, FALSE) != FALSE;
    }

    void serve(HANDLE pipe) {
        OVERLAPPED ov{};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        while (running_ && ov.hEvent) {
            ResetEvent(ov.hEvent);
            DWORD bytes = 0;
            bool connected = ConnectNamedPipe(pipe, &ov) != FALSE;
            if (!connected) {
                const DWORD err = GetLastError();
                if (err == ERROR_PIPE_CONNECTED) connected = true;
                else if (err == ERROR_IO_PENDING) connected = wait_io(pipe, ov, INFINITE, bytes);
            }
            if (connected && running_) answer(pipe, ov);
            DisconnectNamedPipe(pipe);
        }
        if (ov.hEvent) CloseHandle(ov.hEvent);
        CloseHandle(pipe);
    }

    void answer(HANDLE pipe, OVERLAPPED& ov) {
        request req{};
        DWORD bytes = 0;
        ResetEvent(ov.hEvent);
        bool ok = ReadFile(pipe, &req, sizeof(req), &bytes, &ov) != FALSE;
        if (!ok && GetLastError() == ERROR_IO_PENDING) ok = wait_io(pipe, ov, io_timeout_ms_, bytes);
        if (!ok || bytes != sizeof(req) || req.magic != kMagic || req.version != kVersion) {
            rejected_.fetch_add(1);
            return;
        }
        ULONG client = 0;
        if (!GetNamedPipeClientProcessId(pipe, &client) || client == 0) {
            rejected_.fetch_add(1);
            return;
        }
        requests_.fetch_add(1);
        reply rep{};
        try {
            rep = handler_(req, client);
        } catch (const std::exception& e) {
            PC_LOG_WARN("[HOOK-PIPE] handler failed: {}", e.what());
            rep = reply{};
        }
        rep.magic = kMagic;
        ResetEvent(ov.hEvent);
        ok = WriteFile(pipe, &rep, sizeof(rep), &bytes, &ov) != FALSE;
        if (!ok && GetLastError() == ERROR_IO_PENDING) ok = wait_io(pipe, ov, io_timeout_ms_, bytes);
        // DisconnectNamedPipe discards unread reply bytes, while synchronous
        // FlushFileBuffers would block forever on a stalled client (and hang
        // stop()). Wait for the client to close its end (CallNamedPipeW does
        // so right after reading the reply) via a bounded, cancellable
        // overlapped read instead.
        if (ok && running_) {
            char eof = 0;
            ResetEvent(ov.hEvent);
            if (!ReadFile(pipe, &eof, 1, &bytes, &ov) && GetLastError() == ERROR_IO_PENDING) {
                wait_io(pipe, ov, io_timeout_ms_, bytes);
            }
        }
    }

    void cleanup() {
        if (stop_event_) { CloseHandle(stop_event_); stop_event_ = nullptr; }
        if (sd_) { LocalFree(sd_); sd_ = nullptr; }
    }

    handler handler_;
    std::wstring pipe_name_;
    DWORD io_timeout_ms_;
    HANDLE stop_event_{nullptr};
    PSECURITY_DESCRIPTOR sd_{nullptr};
    std::atomic<bool> running_{false};
    std::vector<std::thread> threads_;
    std::atomic<uint64_t> requests_{0};
    std::atomic<uint64_t> rejected_{0};
};

} // namespace clew::hook
