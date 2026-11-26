#pragma once

// Lock-free concurrency limiter for TCP relay coroutines and in-flight SOCKS5
// handshakes (v0.18 #2 resource caps). Pure C++23 (no OS / Asio dependency) so
// it is directly unit tested.
//
// Each accepted TCP relay holds an `active` permit for its full lifetime; the
// SOCKS5 setup phase (DNS resolve + TCP connect + SOCKS5 auth/CONNECT) also
// holds a `pending` permit so a stalled or dead upstream proxy cannot pile up
// unbounded half-open sockets and coroutine frames.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace clew {

class session_limiter {
public:
    static constexpr std::size_t kDefaultMaxActive  = 2048;
    static constexpr std::size_t kDefaultMaxPending = 256;

    // Move-only RAII guard. Releases its slot on destruction or explicit release().
    class permit {
    public:
        permit() noexcept = default;
        ~permit() noexcept { release(); }

        permit(const permit&) = delete;
        permit& operator=(const permit&) = delete;

        permit(permit&& other) noexcept
            : counter_(std::exchange(other.counter_, nullptr)) {}

        permit& operator=(permit&& other) noexcept {
            if (this != &other) {
                release();
                counter_ = std::exchange(other.counter_, nullptr);
            }
            return *this;
        }

        explicit operator bool() const noexcept { return counter_ != nullptr; }

        void release() noexcept {
            if (counter_) {
                counter_->fetch_sub(1, std::memory_order_acq_rel);
                counter_ = nullptr;
            }
        }

    private:
        friend class session_limiter;
        explicit permit(std::atomic<std::size_t>* counter) noexcept : counter_(counter) {}

        std::atomic<std::size_t>* counter_{nullptr};
    };

    struct snapshot {
        std::size_t active{0};
        std::size_t max_active{0};
        std::size_t active_peak{0};
        std::size_t pending{0};
        std::size_t max_pending{0};
        std::size_t pending_peak{0};
        uint64_t    rejected_active{0};
        uint64_t    rejected_pending{0};
    };

    explicit session_limiter(std::size_t max_active  = kDefaultMaxActive,
                             std::size_t max_pending = kDefaultMaxPending) noexcept
        : max_active_(max_active), max_pending_(max_pending) {}

    session_limiter(const session_limiter&) = delete;
    session_limiter& operator=(const session_limiter&) = delete;

    [[nodiscard]] permit try_acquire_active() noexcept {
        return try_acquire(active_, max_active_, active_peak_, rejected_active_);
    }

    [[nodiscard]] permit try_acquire_pending() noexcept {
        return try_acquire(pending_, max_pending_, pending_peak_, rejected_pending_);
    }

    std::size_t max_active() const noexcept { return max_active_; }
    std::size_t max_pending() const noexcept { return max_pending_; }

    snapshot stats() const noexcept {
        return {
            .active           = active_.load(std::memory_order_relaxed),
            .max_active       = max_active_,
            .active_peak      = active_peak_.load(std::memory_order_relaxed),
            .pending          = pending_.load(std::memory_order_relaxed),
            .max_pending      = max_pending_,
            .pending_peak     = pending_peak_.load(std::memory_order_relaxed),
            .rejected_active  = rejected_active_.load(std::memory_order_relaxed),
            .rejected_pending = rejected_pending_.load(std::memory_order_relaxed),
        };
    }

private:
    static permit try_acquire(std::atomic<std::size_t>& counter,
                              std::size_t limit,
                              std::atomic<std::size_t>& peak,
                              std::atomic<uint64_t>& rejected) noexcept {
        std::size_t cur = counter.load(std::memory_order_relaxed);
        for (;;) {
            if (cur >= limit) {
                rejected.fetch_add(1, std::memory_order_relaxed);
                return {};
            }
            if (counter.compare_exchange_weak(cur, cur + 1,
                                              std::memory_order_acq_rel,
                                              std::memory_order_relaxed)) {
                const std::size_t next = cur + 1;
                std::size_t p = peak.load(std::memory_order_relaxed);
                while (next > p &&
                       !peak.compare_exchange_weak(p, next, std::memory_order_relaxed)) {}
                return permit{&counter};
            }
        }
    }

    std::size_t              max_active_;
    std::size_t              max_pending_;
    std::atomic<std::size_t> active_{0};
    std::atomic<std::size_t> active_peak_{0};
    std::atomic<std::size_t> pending_{0};
    std::atomic<std::size_t> pending_peak_{0};
    std::atomic<uint64_t>    rejected_active_{0};
    std::atomic<uint64_t>    rejected_pending_{0};
};

} // namespace clew
