#pragma once

// debouncer — run the most recently scheduled action once things go quiet.
//
// schedule(fn) replaces any pending action and restarts the quiet period; the
// action runs on the debouncer's own thread once `delay` has passed without a
// further schedule(). flush() runs a pending action immediately on the calling
// thread. The destructor flushes, so a scheduled save is never lost on exit.
//
// Used for the window geometry save: WM_EXITSIZEMOVE / maximize bursts end up
// as one config write, and the write (file I/O + observers) happens off the UI
// thread.

#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <stop_token>
#include <thread>
#include <utility>

namespace clew {

class debouncer {
public:
    using clock = std::chrono::steady_clock;

    explicit debouncer(std::chrono::milliseconds delay)
        : delay_(delay)
        , thread_([this](std::stop_token st) { loop(st); }) {}

    ~debouncer() {
        thread_.request_stop();
        if (thread_.joinable()) thread_.join();
        flush();
    }

    debouncer(const debouncer&)            = delete;
    debouncer& operator=(const debouncer&) = delete;

    void schedule(std::function<void()> fn) {
        {
            std::scoped_lock lk(mu_);
            pending_  = std::move(fn);
            deadline_ = clock::now() + delay_;
        }
        cv_.notify_all();
    }

    // Runs the pending action (if any) now, on the calling thread.
    void flush() {
        std::function<void()> fn;
        {
            std::scoped_lock lk(mu_);
            fn = std::exchange(pending_, nullptr);
        }
        if (fn) fn();
    }

    [[nodiscard]] bool has_pending() const {
        std::scoped_lock lk(mu_);
        return static_cast<bool>(pending_);
    }

private:
    void loop(std::stop_token st) {
        std::unique_lock lk(mu_);
        while (!st.stop_requested()) {
            if (!pending_) {
                cv_.wait(lk, st, [this] { return static_cast<bool>(pending_); });
                continue;
            }
            const auto deadline = deadline_;
            if (cv_.wait_until(lk, st, deadline, [this, deadline] {
                    return !pending_ || deadline_ != deadline;
                })) {
                continue;  // rescheduled or flushed meanwhile
            }
            if (st.stop_requested()) break;
            auto fn = std::exchange(pending_, nullptr);
            lk.unlock();
            if (fn) fn();
            lk.lock();
        }
    }

    const std::chrono::milliseconds delay_;
    mutable std::mutex              mu_;
    std::condition_variable_any     cv_;
    std::function<void()>           pending_;
    clock::time_point               deadline_{};
    std::jthread                    thread_;  // last: starts after the state above exists
};

} // namespace clew
