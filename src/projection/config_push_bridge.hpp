#pragma once

// config_push_bridge — subscribes to config_store and turns each
// config_change tag into a frontend `auto_rule_changed` push with an
// `action` field. Construction-time wiring only; the sink can be set
// later (after the WebView2 host is created in app.cpp).

#include <atomic>

namespace clew {

class config_store;
class frontend_push_sink;

class config_push_bridge {
public:
    explicit config_push_bridge(config_store& cfg);

    config_push_bridge(const config_push_bridge&)            = delete;
    config_push_bridge& operator=(const config_push_bridge&) = delete;

    void set_sink(frontend_push_sink* sink) noexcept { sink_.store(sink); }

private:
    std::atomic<frontend_push_sink*> sink_{nullptr};
};

} // namespace clew
