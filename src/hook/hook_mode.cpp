#include "hook/hook_mode.hpp"

#include <chrono>
#include <cstring>
#include <future>
#include <set>

#include "core/ip_family.hpp"
#include "core/log.hpp"
#include "rules/rule_engine_v3.hpp"

namespace clew::hook {

namespace {

constexpr auto kSweepPeriod     = std::chrono::seconds(1);
constexpr auto kDecisionTimeout = std::chrono::seconds(2);

uint32_t v4_host_order(const uint8_t* b) {
    return (uint32_t{b[0]} << 24) | (uint32_t{b[1]} << 16) | (uint32_t{b[2]} << 8) | b[3];
}

bool is_v4_unroutable(uint32_t ip) {
    return (ip >> 24) == 127 || ip == 0;
}

reply make_reply(verdict v, uint16_t port = 0, uint32_t error = 0) {
    reply r{};
    r.magic = kMagic;
    r.verdict = static_cast<uint32_t>(v);
    r.relay_port = port;
    r.error = error;
    return r;
}

} // namespace

mode::mode(asio::io_context& ioc, strand_type& strand, domain::process_tree_manager& tree_mgr,
           const proxy_group_table& groups, ipv6_egress& egress, DecisionLog* decisions,
           const std::atomic<bool>& ipv6_block, const std::atomic<bool>& ipv6_proxy)
    : ioc_(ioc)
    , strand_(strand)
    , tree_mgr_(tree_mgr)
    , groups_(groups)
    , egress_(egress)
    , decisions_(decisions)
    , ipv6_block_(ipv6_block)
    , ipv6_proxy_(ipv6_proxy)
    , self_pid_(GetCurrentProcessId())
    , acceptor_v4_(ioc, flows_, groups, false)
    , acceptor_v6_(ioc, flows_, groups, true, &egress)
    , sweep_timer_(ioc)
{}

mode::~mode() { stop(); }

bool mode::start(const std::filesystem::path& dll) {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(dll, ec)) {
        PC_LOG_ERROR("[HOOK] {} not found next to proxyclaw.exe: hook mode cannot intercept anything",
                     dll.filename().string());
        return false;
    }
    dll_path_ = dll.wstring();
    enable_debug_privilege();

    port_v4_ = acceptor_v4_.start();
    port_v6_ = acceptor_v6_.start();
    if (port_v4_ == 0) {
        PC_LOG_ERROR("[HOOK] relay listener failed: hook mode disabled");
        return false;
    }

    pipe_ = std::make_unique<pipe_server>(
        [this](const request& req, DWORD pid) { return on_request(req, pid); });
    if (!pipe_->start()) {
        acceptor_v4_.stop();
        acceptor_v6_.stop();
        pipe_.reset();
        return false;
    }

    running_ = true;
    injector_ = std::jthread([this](std::stop_token st) { injector_loop(st); });
    asio::post(strand_, [this] { schedule_sweep(); });
    PC_LOG_INFO("[HOOK] interception mode: hook (relay {} / {}, dll {})",
                port_v4_, port_v6_, dll.string());
    return true;
}

void mode::stop() {
    if (!running_.exchange(false)) return;
    // The pipe first: nothing new gets decided while the rest goes down.
    if (pipe_) pipe_->stop();
    asio::post(strand_, [this] { sweep_timer_.cancel(); });
    if (injector_.joinable()) {
        injector_.request_stop();
        inj_cv_.notify_all();
        injector_.join();
    }
    acceptor_v4_.stop();
    acceptor_v6_.stop();
    PC_LOG_INFO("[HOOK] stopped (proxy={} direct={} block={} injected={} children={})",
                n_proxy_.load(), n_direct_.load(), n_block_.load(), n_inject_ok_.load(),
                n_child_inject_.load());
}

// ---------------------------------------------------------------------------
// Pipe side: hop onto the strand, wait (bounded) for its answer.

reply mode::on_request(const request& req, DWORD client_pid) {
    if (!running_) return make_reply(verdict::direct);
    auto done = std::make_shared<std::promise<reply>>();
    auto fut = done->get_future();
    asio::post(strand_, [this, req, client_pid, done] {
        try {
            const auto type = static_cast<msg_type>(req.type);
            if (type == msg_type::connect)    done->set_value(decide_connect(req, client_pid));
            else if (type == msg_type::child) done->set_value(decide_child(client_pid, req.child_pid));
            else                              done->set_value(make_reply(verdict::direct));
        } catch (...) {
            done->set_value(make_reply(verdict::direct));
        }
    });
    if (fut.wait_for(kDecisionTimeout) != std::future_status::ready) {
        n_timeout_.fetch_add(1);
        PC_LOG_WARN("[HOOK] decision for PID {} timed out: direct", client_pid);
        return make_reply(verdict::direct);
    }
    return fut.get();
}

// ---------------------------------------------------------------------------
// Strand side.

reply mode::decide_connect(const request& req, DWORD pid) {
    DecisionRecord rec;
    rec.pid = pid;
    rec.reason = decision_reason::not_proxied;
    const bool v6 = req.family == 6;
    auto direct = [&](decision_reason why) {
        rec.reason = why;
        record(req, pid, rec);
        n_direct_.fetch_add(1);
        return make_reply(verdict::direct);
    };

    if (pid == self_pid_) return direct(decision_reason::self);
    if (!v6 && is_v4_unroutable(v4_host_order(req.dst))) return direct(decision_reason::global_exclude);

    if (!tree_mgr_.resolve_pid_now(pid)) return direct(decision_reason::unknown_pid);
    const auto& tree = tree_mgr_.tree();
    const uint32_t idx = tree.find_by_pid(pid);
    if (idx == INVALID_IDX) return direct(decision_reason::unknown_pid);
    const auto& entry = tree.at(idx);
    rec.psn = entry.psn;
    if (!entry.alive || !entry.is_proxied()) return direct(decision_reason::not_proxied);

    const auto& rules = tree_mgr_.rules();
    const auto origin = rules.origin_of(entry);
    rec.source = origin.source;
    rec.policy_id = origin.policy_id;

    flow f;
    f.port = req.dst_port;
    f.group_id = entry.group_id;
    f.pid = pid;
    uint16_t relay = port_v4_;

    if (!v6) {
        f.v4_host = v4_host_order(req.dst);
        const auto why = rules.route_reason(tree, pid, false, f.v4_host, req.dst_port);
        if (why != IpExcludeReason::none) return direct(to_decision_reason(why));
    } else {
        std::memcpy(f.v6.data(), req.dst, 16);
        const auto why = rules.route_reason_v6(tree, pid, false, is_local_scope_ipv6(req.dst),
                                               req.dst, req.dst_port);
        if (why != IpExcludeReason::none) return direct(to_decision_reason(why));
        if (!ipv6_block_.load(std::memory_order_relaxed)) return direct(decision_reason::ipv6);
        const bool proxy_v6 = ipv6_proxy_.load(std::memory_order_relaxed) && port_v6_ != 0;
        if (!proxy_v6 || egress_.unavailable(entry.group_id)) {
            rec.reason = proxy_v6 ? decision_reason::ipv6_no_egress : decision_reason::ipv6_blocked;
            record(req, pid, rec);
            n_block_.fetch_add(1);
            return make_reply(verdict::block, 0, WSAENETUNREACH);
        }
        f.ipv6 = true;
        relay = port_v6_;
    }

    flows_.publish(v6, req.src_port, f);
    rec.verdict = decision_verdict::proxied;
    rec.reason = decision_reason::none;
    rec.group_id = entry.group_id;
    record(req, pid, rec);
    n_proxy_.fetch_add(1);
    PC_LOG_DEBUG("[HOOK] proxy PID={} port={} group={} -> relay {}", pid, req.src_port,
                 entry.group_id, relay);
    return make_reply(verdict::proxy, relay);
}

reply mode::decide_child(DWORD parent, DWORD child) {
    // The child is suspended and not in the tree yet (ETW is ~1-2 s behind):
    // resolve it now, which classifies it with its ancestors' rules.
    if (child == 0 || child == self_pid_ || !tree_mgr_.resolve_pid_now(child)) {
        n_child_skip_.fetch_add(1);
        return make_reply(verdict::direct);
    }
    const auto& tree = tree_mgr_.tree();
    const uint32_t idx = tree.find_by_pid(child);
    if (idx == INVALID_IDX || !tree.at(idx).is_proxied()) {
        n_child_skip_.fetch_add(1);
        return make_reply(verdict::direct);
    }
    {
        // The DLL injects it itself; the sweep must not try a second time
        // while the child is still suspended.
        std::lock_guard lock(inj_mu_);
        inj_done_[{child, tree.at(idx).psn}] = inject_result::ok;
    }
    n_child_inject_.fetch_add(1);
    PC_LOG_DEBUG("[HOOK] child PID={} of PID={} gets the DLL", child, parent);
    return make_reply(verdict::proxy);
}

void mode::record(const request& req, DWORD pid, DecisionRecord& rec) {
    if (!decisions_) return;
    rec.pid = pid;
    rec.proto = decision_proto::tcp;
    rec.local_port = req.src_port;
    rec.remote_port = req.dst_port;
    if (req.family == 6) {
        rec.flags |= decision_flags::IPV6;
        // Host-order words, least significant first (ip_family.hpp).
        for (int i = 0; i < 4; ++i)
            rec.remote_addr[3 - i] = v4_host_order(req.dst + i * 4);
    } else {
        rec.remote_addr[0] = v4_host_order(req.dst);
    }
    rec.config_version = tree_mgr_.rules().config_version();
    rec.at_ms = decision_now_ms();
    decisions_->record(rec);
}

void mode::schedule_sweep() {
    if (!running_) return;
    std::vector<key> wanted;
    for (const auto& e : tree_mgr_.tree().entries()) {
        if (e.alive && e.is_proxied() && e.pid != self_pid_ && e.pid > 4)
            wanted.emplace_back(e.pid, e.psn);
    }
    {
        std::lock_guard lock(inj_mu_);
        inj_wanted_ = std::move(wanted);
        inj_dirty_ = true;
    }
    inj_cv_.notify_one();
    flows_.prune();
    sweep_timer_.expires_after(kSweepPeriod);
    sweep_timer_.async_wait(asio::bind_executor(strand_, [this](const std::error_code& ec) {
        if (!ec) schedule_sweep();
    }));
}

// ---------------------------------------------------------------------------
// Injector thread: OpenProcess / CreateRemoteThread can block for seconds,
// so it never runs on the strand.

void mode::injector_loop(std::stop_token st) {
    while (!st.stop_requested()) {
        std::vector<key> wanted;
        {
            std::unique_lock lock(inj_mu_);
            inj_cv_.wait(lock, st, [this] { return inj_dirty_; });
            if (st.stop_requested()) return;
            wanted = inj_wanted_;
            inj_dirty_ = false;
        }
        std::set<key> live(wanted.begin(), wanted.end());
        for (const auto& k : wanted) {
            if (st.stop_requested()) return;
            {
                std::lock_guard lock(inj_mu_);
                if (inj_done_.contains(k)) continue;
            }
            const auto r = inject_into(k.first, dll_path_);
            {
                std::lock_guard lock(inj_mu_);
                inj_done_[k] = r;
            }
            switch (r) {
            case inject_result::ok:
                n_inject_ok_.fetch_add(1);
                PC_LOG_INFO("[HOOK] injected PID {}", k.first);
                break;
            case inject_result::wow64:
            case inject_result::restricted:
            case inject_result::signed_only:
                n_inject_skip_.fetch_add(1);
                PC_LOG_INFO("[HOOK] PID {} not injected ({}): its connections stay direct",
                            k.first, inject_result_name(r));
                break;
            default:
                n_inject_fail_.fetch_add(1);
                PC_LOG_WARN("[HOOK] injecting PID {} failed ({})", k.first, inject_result_name(r));
                break;
            }
        }
        // Forget processes that exited or stopped being proxied.
        std::lock_guard lock(inj_mu_);
        for (auto it = inj_done_.begin(); it != inj_done_.end();) {
            if (!live.contains(it->first)) it = inj_done_.erase(it);
            else ++it;
        }
    }
}

nlohmann::json mode::stats() const {
    const auto f = flows_.snapshot();
    return {
        {"relay_port", port_v4_},
        {"relay_port_v6", port_v6_},
        {"pipe_requests", pipe_ ? pipe_->requests() : 0},
        {"pipe_rejected", pipe_ ? pipe_->rejected() : 0},
        {"proxied", n_proxy_.load()},
        {"direct", n_direct_.load()},
        {"blocked", n_block_.load()},
        {"decision_timeouts", n_timeout_.load()},
        {"injected", n_inject_ok_.load()},
        {"inject_skipped", n_inject_skip_.load()},
        {"inject_failed", n_inject_fail_.load()},
        {"children_injected", n_child_inject_.load()},
        {"children_skipped", n_child_skip_.load()},
        {"relay_accepted", acceptor_v4_.accepted() + acceptor_v6_.accepted()},
        {"relay_unmatched", acceptor_v4_.unmatched() + acceptor_v6_.unmatched()},
        {"flows_pending", f.pending},
        {"flows_expired", f.expired},
    };
}

} // namespace clew::hook
