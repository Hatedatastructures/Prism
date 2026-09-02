#include <prism/diagnose/diagnose.hpp>
#include <prism/protocol/multiplex/datagram.hpp>
#include <prism/protocol/multiplex/multiplexer.hpp>
#include <prism/protocol/multiplex/stream.hpp>

#include <boost/asio/co_spawn.hpp>

#include <ranges>
#include <span>

using namespace psm::diagnose;

namespace
{
    auto resolve_mr(psm::memory::resource_pointer mr) -> psm::memory::resource_pointer
    {
        if (mr)
        {
            return mr;
        }
        return psm::memory::current_resource();
    }
} // namespace

namespace psm::multiplex
{

    multiplexer::multiplexer(multiplexer_options opts)
        : transport_(std::move(opts.transport)), outbound_(opts.outbound), config_(opts.cfg),
          mr_(resolve_mr(opts.mr)), pending_(mr_), streams_(mr_), datagrams_(mr_),
          channel_(transport_->executor(), opts.channel_capacity)
    {
    }

    multiplexer::~multiplexer() noexcept
    {
        close();
    }

    void multiplexer::start()
    {
        active_.store(true, std::memory_order_release);

        auto self = shared_from_this();

        net::co_spawn(transport_->executor(), run_owned(self),
                      [self](const std::exception_ptr &ep) { self->on_exception(ep); });

        net::co_spawn(transport_->executor(), send_owned(std::move(self)), net::detached);
    }

    void multiplexer::on_exception(const std::exception_ptr &ep)
    {
        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                diagnose::error(prefix_, "session exception: {}", e.what());
            }
            catch (...)
            {
                diagnose::error(prefix_, "session unknown exception");
            }
        }
        close();
    }

    void multiplexer::close()
    {
        if (!active_.exchange(false, std::memory_order_acq_rel))
        {
            return;
        }

        transport_->cancel();
        channel_.cancel();

        pending_.clear();

        for (auto streams = std::move(streams_); auto &p : streams | std::views::values)
        {
            if (p)
            {
                p->close();
            }
        }
        for (auto datagrams = std::move(datagrams_); auto &p : datagrams | std::views::values)
        {
            if (p)
            {
                p->close();
            }
        }

        transport_->close();

        diagnose::debug(prefix_, "session closed");
    }

    auto multiplexer::send(const std::uint32_t stream_id, memory::vector<std::byte> payload)
        -> net::awaitable<void>
    {
        if (!is_active())
        {
            co_return;
        }

        outbound_frame frame;
        frame.stream_id = stream_id;
        frame.payload = std::move(payload);
        frame.kind = outbound_kind::data;
        co_await push_frame(std::move(frame));
    }

    void multiplexer::drop(const std::uint32_t stream_id)
    {
        streams_.erase(stream_id);
        datagrams_.erase(stream_id);
        pending_.erase(stream_id);
    }

    void multiplexer::fin(const std::uint32_t stream_id)
    {
        if (!is_active())
        {
            return;
        }

        outbound_frame frame;
        frame.stream_id = stream_id;
        frame.kind = outbound_kind::fin;

        // 通道满时丢弃 fin 帧（会话即将关闭，丢失结束通知可接受）
        channel_.try_send(boost::system::error_code{}, std::move(frame));
    }

    auto multiplexer::push_frame(outbound_frame frame) -> net::awaitable<void>
    {
        if (!is_active())
        {
            co_return;
        }

        boost::system::error_code ec;
        auto token = net::redirect_error(net::use_awaitable, ec);
        co_await channel_.async_send(boost::system::error_code{}, std::move(frame), token);
    }

    auto multiplexer::send_loop() -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "send loop started");
        try
        {
            while (is_active())
            {
                boost::system::error_code ec;
                auto token = net::redirect_error(net::use_awaitable, ec);
                auto frame = co_await channel_.async_receive(token);
                if (ec)
                {
                    break;
                }

                co_await write_frame(std::move(frame));
            }
        }
        catch (const std::exception &e)
        {
            diagnose::debug(prefix_, "send loop error: {}", e.what());
        }
        catch (...)
        {
            diagnose::debug(prefix_, "send loop unknown error");
        }
        diagnose::debug(prefix_, "send loop ended");
    }

    auto multiplexer::run_owned(std::shared_ptr<multiplexer> self) -> net::awaitable<void>
    {
        co_await self->run();
    }

    auto multiplexer::send_owned(std::shared_ptr<multiplexer> self) -> net::awaitable<void>
    {
        co_await self->send_loop();
    }

} // namespace psm::multiplex
