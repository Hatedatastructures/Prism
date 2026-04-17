#include <prism/multiplex/core.hpp>
#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/parcel.hpp>
#include <prism/trace.hpp>
#include <ranges>
#include <span>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Mux.Core]";

namespace psm::multiplex
{
    core::core(channel::transport::shared_transmission transport, resolve::router &router,
               const config &cfg, const memory::resource_pointer mr)
        : transport_(std::move(transport)), router_(router), config_(cfg),      
          mr_(mr ? mr : memory::current_resource()),
          pending_(mr_), ducts_(mr_), parcels_(mr_)
    {
    }

    core::~core()
    {
        close();
    }

    void core::start()
    {
        active_.store(true, std::memory_order_release);

        auto exception_functor = [self = shared_from_this()](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::error("{} session exception: {}", tag, e.what());
                }
                catch (...)
                {
                    trace::error("{} session unknown exception", tag);
                }
            }
            self->close();
        };

        auto run_wrapper = [self = shared_from_this()]() -> net::awaitable<void>
        {
            co_await self->run();
        };
        net::co_spawn(transport_->executor(), run_wrapper(), std::move(exception_functor));
    }

    void core::close()
    {
        if (!active_.exchange(false, std::memory_order_acq_rel))
        {
            return;
        }

        transport_->cancel();

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

        trace::debug("{} session closed", tag);
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