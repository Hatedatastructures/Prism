#include <prism/runtime/worker/worker.hpp>

#include <prism/foundation/coroutine/registry.hpp>
#include <prism/runtime/worker/launch.hpp>
#include <prism/runtime/worker/tls.hpp>
#include <prism/trace/trace.hpp>

#include <boost/asio/co_spawn.hpp>

#include <memory>
#include <utility>

using namespace psm::trace;

namespace psm::runtime::worker
{

    worker::worker(std::shared_ptr<psm::resource::process> global_ctx)
        : resources_(std::make_shared<psm::resource::worker>(
              psm::resource::worker::options{
                  std::move(global_ctx),
                  std::pmr::new_delete_resource(),
                  0}))
    {
    }

    auto worker::run() -> void
    {
        resources_->tasks.spawn_tracked(
            "metrics.observe", metrics_.observe(resources_->ioc));
        resources_->ioc.run();
    }

    auto worker::stop() -> void
    {
        resources_->stop();
    }

    worker::~worker() = default;

    auto worker::dispatch_socket(tcp::socket socket) -> void
    {
        launch::dispatch(launch::launch_params{
            resources_, metrics_, std::move(socket)});
    }

    auto worker::load_snapshot() const noexcept
        -> ::psm::stats::worker_snapshot
    {
        auto snapshot = metrics_.snapshot();
        const auto task_stats = resources_->tasks.stats();
        snapshot.active_tasks = task_stats.active;
        snapshot.spawned_total = task_stats.total_spawned;
        snapshot.cancelled_total = task_stats.total_cancelled;
        snapshot.alive = resources_->alive();
        return snapshot;
    }

} // namespace psm::runtime::worker
