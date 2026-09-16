#include <prism/diagnose/diagnose.hpp>
#include <prism/foundation/coroutine/registry.hpp>
#include <prism/runtime/worker/launch.hpp>
#include <prism/runtime/worker/tls.hpp>
#include <prism/runtime/worker/worker.hpp>

#include <boost/asio/co_spawn.hpp>

#include <memory>
#include <utility>

using namespace psm::diagnose;

namespace psm::runtime::worker
{

    worker::worker(std::shared_ptr<psm::resource::process> global_ctx, ConnectionLauncher launcher)
        : resources_(std::make_shared<psm::resource::worker>(
              psm::resource::worker::options{std::move(global_ctx), std::pmr::new_delete_resource(), 0})),
          metrics_(std::make_shared<psm::stats::runtime::worker_load>()), launcher_(std::move(launcher)),
          dispatch_state_(std::make_shared<launch::dispatch_state>())
    {
    }

    auto worker::run() -> void
    {
        resources_->tasks.spawn_tracked("metrics.observe", metrics_->observe(resources_->ioc));
        resources_->ioc.run();
    }

    auto worker::stop() -> void
    {
        dispatch_state_->cancel();
        resources_->stop();
    }

    worker::~worker() = default;

    auto worker::dispatch_socket(tcp::socket socket) -> void
    {
        launch::dispatch(launch::launch_params{resources_, metrics_, std::move(socket)}, launcher_,
                         dispatch_state_);
    }

    auto worker::load_snapshot() const noexcept -> ::psm::stats::worker_snapshot
    {
        auto snapshot = metrics_->snapshot();
        const auto task_stats = resources_->tasks.stats();
        snapshot.active_tasks = task_stats.active;
        snapshot.spawned_total = task_stats.total_spawned;
        snapshot.cancelled_total = task_stats.total_cancelled;
        return snapshot;
    }

} // namespace psm::runtime::worker
