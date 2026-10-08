// Real projection scheduling with an in-memory tree; no ETW, proxy or system DNS.
#include "projection/process_projection.hpp"
#include "domain/process_tree_manager.hpp"
#include "transport/frontend_push_sink.hpp"
#include <iostream>
#include <stdexcept>
#include <vector>

struct recording_sink : clew::frontend_push_sink {
    std::vector<std::string> messages;
    void push(std::string_view, std::string data) override { messages.push_back(std::move(data)); }
};
static void check(bool ok, const char* message) {
    if (!ok) throw std::runtime_error(message);
}

int main() {
    try {
        asio::io_context ioc;
        auto strand = asio::make_strand(ioc);
        clew::domain::process_tree_manager manager;
        clew::process_projection projection(manager, strand);
        recording_sink sink;
        projection.set_sink(&sink);
        auto drain = [&] { ioc.restart(); ioc.poll(); };
        auto wait = [&] { ioc.restart(); ioc.run_for(std::chrono::milliseconds(130)); };
        projection.set_frontend_visible(false);
        asio::post(strand, [&] { projection.on_tree_changed(clew::push_urgency::batched); });
        wait();
        check(sink.messages.empty() && manager.tree().serializations == 0,
              "hidden startup must not serialize or push");
        manager.tree().json = "[{\"pid\":42}]";
        projection.set_frontend_visible(true); drain();
        check(sink.messages.size() == 1 && sink.messages.back() == manager.tree().json,
              "restore must push current tree without a new process event");
        projection.set_frontend_visible(true); drain();
        check(sink.messages.size() == 1, "repeated visible state must not replay");
        asio::post(strand, [&] { projection.on_tree_changed(clew::push_urgency::batched); });
        drain();
        projection.set_frontend_visible(false); wait();
        check(sink.messages.size() == 1, "already queued flush must stop when hidden");
        projection.set_frontend_visible(true);
        projection.set_frontend_visible(false); drain();
        check(sink.messages.size() == 1, "queued restore must be suppressed after hiding again");
        projection.set_frontend_visible(true); drain();
        auto before = sink.messages.size();
        asio::post(strand, [&] {
            projection.on_tree_changed(clew::push_urgency::batched);
            projection.on_tree_changed(clew::push_urgency::immediate);
            projection.on_tree_changed(clew::push_urgency::batched);
        });
        drain();
        // Deliver another batched event after the cancelled old wait has run.
        // It must join the existing 100ms flush rather than postpone it to 150ms.
        asio::steady_timer followup(strand);
        followup.expires_after(std::chrono::milliseconds(50));
        followup.async_wait([&](std::error_code ec) {
            if (!ec) projection.on_tree_changed(clew::push_urgency::batched);
        });
        ioc.restart(); ioc.run_for(std::chrono::milliseconds(125));
        check(sink.messages.size() == before + 2,
              "cancelled old timer must not interfere with a new flush");
        std::cout << "PASS: 6 projection visibility/coalescing scenarios\n";
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n'; return 1;
    }
}
