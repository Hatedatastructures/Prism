#include <prism/memory/container.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/stats/traffic.hpp>
#include <prism/trace.hpp>
#include <prism/trace/context.hpp>

#include <boost/asio/co_spawn.hpp>

#include <ranges>
#include <span>

using namespace psm::trace;

namespace
{
    auto resolve_mr(psm::memory::resource_pointer mr) -> psm::memory::resource_pointer
    {
        if (mr)
            return mr;
        return psm::memory::current_resource();
    }
} // namespace

namespace psm::multiplex
{

    core::core(core_options opts)
        : transport_(std::move(opts.transport)), router_(opts.router), config_(opts.cfg),
          mr_(resolve_mr(opts.mr)),
          pending_(mr_), ducts_(mr_), parcels_(mr_)
    {
    }


    core::~core() noexcept
    {
        close();
    }


    void core::start()
    {
        active_.store(true, std::memory_order_release);

        auto self = shared_from_this();

        auto run_wrapper = [self]() -> net::awaitable<void>
        {
            trace::scope_guard guard(self->prefix_);
            co_await self->run();
        };
        net::co_spawn(transport_->executor(), run_wrapper(),
            [self](const std::exception_ptr &ep)
            {
                self->on_exception(ep);
            });
    }


    void core::on_exception(const std::exception_ptr &ep)
    {
        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                trace::error<flt::conn | flt::protocol>("session exception: {}", e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>("session unknown exception");
            }
        }
        close();
    }


    void core::close()
    {
        if (!active_.exchange(false, std::memory_order_acq_rel))
        {
            return;
        }

        transport_->cancel();

        if (traffic_)
        {
            const auto up = mux_uplink_.load(std::memory_order_relaxed);
            const auto down = mux_downlink_.load(std::memory_order_relaxed);
            traffic_->flush_traffic(proto_, up, down);
        }

        pending_.clear();

        // std::move 避免 iterator invalidation：close() 中 duct 调用
        // remove_duct/remove_parcel 对空 map 操作
        for (auto ducts = std::move(ducts_); auto &p : ducts | std::views::values)
        {
            if (p)
            {
                p->close();
            }
        }
        for (auto parcels = std::move(parcels_); auto &p : parcels | std::views::values)
        {
            if (p)
            {
                p->close();
            }
        }

        transport_->close();

        trace::debug<flt::conn | flt::protocol>("session closed");
    }


    void core::remove_duct(const std::uint32_t stream_id)
    {
        ducts_.erase(stream_id);
    }


    void core::remove_parcel(const std::uint32_t stream_id)
    {
        parcels_.erase(stream_id);
    }

} // namespace psm::multiplex