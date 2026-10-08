#pragma once

// process_projection — materialized tree JSON snapshot + frontend push
// fan-out for tree-change events.
//
// Registered as a tree_change_receiver on process_tree_manager in app.cpp.
// DESIGN H3: holds domain::process_tree_manager& directly (not
// strand_bound_manager) because on_tree_changed is already invoked inside
// the strand; wrapping it in strand_bound.query() here would deadlock.
//
// Default (no compile flag): every ETW event triggers an immediate
// refresh + push. Snappy at any normal tree size — refresh is ~2us per
// process (≈2ms at tree=1000) and ETW rate is typically <30/sec on a
// quiet box. Even at 1000+ processes the strand stays well under 5%.
//
// PROXYCLAW_PROJECTION_COALESCE compile flag: arms a 100ms refresh-coalesce
// timer for `batched` urgency. Folds bursts of dozens to hundreds of
// ETW events (parallel build kicks off 1000+ child processes at once)
// into a single refresh+push at the end of the window. Trade-off: tree
// updates can lag up to 100ms. `immediate` urgency (user actions) still
// bypasses the timer.
//
// Visibility gate: set_frontend_visible(false) makes on_tree_changed
// drop both refresh and push so the strand stays free while the host
// has the WebView2 controller hidden (minimize / tray). A transition
// back to visible replays the latest tree even without new ETW events.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef ASIO_STANDALONE
#define ASIO_STANDALONE
#endif

#include <atomic>
#include <memory>
#include <string>

#include <asio.hpp>
#ifdef PROXYCLAW_PROJECTION_COALESCE
#include <asio/steady_timer.hpp>
#endif

#include "domain/tree_change_receiver.hpp"

namespace clew {

namespace domain { class process_tree_manager; }
class frontend_push_sink;

class process_projection : public tree_change_receiver {
public:
    using strand_type = asio::strand<asio::io_context::executor_type>;

    process_projection(domain::process_tree_manager& mgr, strand_type& strand);

    ~process_projection() override = default;

    process_projection(const process_projection&)            = delete;
    process_projection& operator=(const process_projection&) = delete;

    // Wired from app.cpp once the WebView2 host (which implements the sink)
    // has been created. Setting to nullptr is safe — push() short-circuits.
    void set_sink(frontend_push_sink* sink) noexcept { sink_.store(sink); }

    // Visibility hand-off from webview_app::set_visible. Hidden -> we drop
    // on_tree_changed work entirely; becoming visible queues a fresh replay.
    void set_frontend_visible(bool v) {
        bool previous = frontend_visible_.exchange(v, std::memory_order_relaxed);
        if (v && !previous) replay_to_frontend();
    }

    // tree_change_receiver. Invoked on the strand.
    void on_tree_changed(push_urgency urgency) override;

    // Replay the most-recent snapshot to the sink. Posted to the strand
    // from the ready-handshake path on the UI thread; refreshes the
    // snapshot then pushes immediately, cancelling any pending coalesce.
    void replay_to_frontend();

private:
    void refresh_snapshot();        // strand only
    void push_current_snapshot();   // strand only
#ifdef PROXYCLAW_PROJECTION_COALESCE
    void schedule_coalesced_push(); // strand only — arms timer if not already pending
#endif

    domain::process_tree_manager&    mgr_;
    strand_type&                     strand_;
#ifdef PROXYCLAW_PROJECTION_COALESCE
    asio::steady_timer               coalesce_timer_;
    bool                             pending_flush_{false};
#endif

    std::atomic<frontend_push_sink*>                sink_{nullptr};
    // The shared_ptr atomic free functions also support standard libraries
    // that do not yet implement atomic<shared_ptr<T>>.
    std::shared_ptr<const std::string> snapshot_;
    std::atomic<bool>                               frontend_visible_{true};
};

} // namespace clew
