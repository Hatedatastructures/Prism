#include <prism/proto/multiplex/duct.hpp>
#include <prism/core/fault/handling.hpp>
#include <prism/proto/multiplex/core.hpp>
#include <prism/trace/trace.hpp>
#include <prism/trace/context.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/net/transport/transmission.hpp>

#include <boost/asio/co_spawn.hpp>

#include <atomic>
#include <span>

using namespace psm::trace;

namespace psm::multiplex
{

    namespace net = boost::asio;

    // 帧载荷最大长度（uint16_t 最大值，所有 mux 协议通用上限）
    constexpr std::size_t max_frame_payload = 65535;

    duct::duct(duct_options opts)
        : id_(opts.stream_id), owner_(std::move(opts.owner)), mr_(opts.opts.mr),
          target_(std::move(opts.target)),
          write_channel_(target_->executor(), 32)
    {
        // 限制读取大小不超过帧载荷上限，防止 send_data 时 uint16_t 溢出
        read_size_ = std::min(opts.opts.buffer_size, static_cast<std::uint32_t>(max_frame_payload));
    }


    duct::~duct() noexcept
    {
        close();
    }


    void duct::start()
    {
        auto self = shared_from_this();

        // target 读循环：target → mux → 客户端（客户端下载方向）
        // 退出时关闭整个管道
        net::co_spawn(target_->executor(), target_readloop_core(),
            [self](const std::exception_ptr &ep)
            {
                self->on_read_done(ep);
            });

        // target 写循环：客户端 → mux → write_channel_ → target（客户端上传方向）
        // 不触发 close，由 target_readloop 退出或自身写错误触发
        net::co_spawn(target_->executor(), target_writeloop_core(),
            [self](const std::exception_ptr &ep)
            {
                self->on_write_done(ep);
            });
    }


    auto duct::target_readloop_core()
        -> net::awaitable<void>
    {
        // 绑定 owner 的 prefix 副本，防止 co_spawn 后 active_prefix 指向已析构对象
        if (auto owner = owner_.lock())
        {
            trace::scope_guard guard(owner->prefix_);
            co_await target_readloop();
        }
        else
        {
            co_await target_readloop();
        }
    }


    auto duct::target_writeloop_core()
        -> net::awaitable<void>
    {
        if (auto owner = owner_.lock())
        {
            trace::scope_guard guard(owner->prefix_);
            co_await target_writeloop();
        }
        else
        {
            co_await target_writeloop();
        }
    }


    void duct::on_read_done(const std::exception_ptr &ep)
    {
        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                trace::debug<flt::conn | flt::protocol>("stream {} target read loop error: {}", id_, e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>("stream {} target read loop unknown error", id_);
            }
        }
        close();
    }


    void duct::on_write_done(const std::exception_ptr &ep)
    {
        if (ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception &e)
            {
                trace::debug<flt::conn | flt::protocol>("stream {} target write loop error: {}", id_, e.what());
            }
            catch (...)
            {
                trace::error<flt::conn | flt::protocol>("stream {} target write loop unknown error", id_);
            }
        }
    }


    auto duct::on_data(memory::vector<std::byte> data)
        -> net::awaitable<void>
    {
        if (closed_)
        {
            co_return;
        }

        boost::system::error_code ch_ec;
        auto token = net::redirect_error(trace::use_prefix_awaitable, ch_ec);
        co_await write_channel_.async_send(boost::system::error_code{}, std::move(data), token);
        if (ch_ec)
        {
            // 通道已关闭或取消，静默退出
            co_return;
        }
    }


    void duct::on_fin()
    {
        // mux 端半关闭，shutdown target 发送方向
        mux_closed_.store(true, std::memory_order_release);

        if (target_)
        {
            if (auto *rel = target_->lowest_layer<transport::reliable>())
            {
                rel->shutdown_write();
            }
            trace::debug<flt::conn | flt::protocol>("stream {} mux fin, shutdown target write", id_);
        }

        // target 端也已关闭，完全关闭管道
        if (target_closed_.load(std::memory_order_acquire))
        {
            close();
        }
    }


    void duct::close()
    {
        if (closed_)
        {
            return;
        }
        closed_ = true;

        // 关闭写通道，通知 target_writeloop 退出
        write_channel_.cancel();

        // 先关闭 target socket（取消所有 pending 异步操作），但不立即释放对象。
        // target_writeloop 可能正 co_await 在 async_write 上，completion handler 需要
        // target 对象在 close() 返回后、handler 执行时仍然存活。
        // target_ 将在 duct 析构时自然释放，此时所有协程已完成。
        if (target_)
        {
            target_->close();
        }

        try
        {
            if (auto owner = owner_.lock())
            {
                owner->accumulate_traffic(
                    written_bytes_.load(std::memory_order_relaxed),
                    read_bytes_.load(std::memory_order_relaxed));
                owner->remove_duct(id_);
            }
        }
        catch (...)
        {
            trace::error<flt::conn | flt::protocol>("stream {} remove duct error", id_);
        }

        trace::debug<flt::conn | flt::protocol>("stream {} closed", id_);
    }


    // target 读循环（客户端下行/下载方向）
    // 从 target 读取数据，通过 owner_->send_data 发回 mux 客户端。
    // 数据直接读入 PMR vector 并 move 传递，零额外拷贝。
    auto duct::target_readloop()
        -> net::awaitable<void>
    {
        std::error_code ec;

        // 将 data 提到循环外，每次迭代仅 resize 复用已分配内存，避免重复分配
        memory::vector<std::byte> data(mr_);

        while (!closed_)
        {
            // mux 端已半关闭（客户端发送 FIN），停止发送数据
            // yamux 协议：客户端 FIN 后不再发送 WindowUpdate，继续发送会窗口耗尽
            if (mux_closed_.load(std::memory_order_acquire))
            {
                trace::debug<flt::conn | flt::protocol>("stream {} mux closed, stop sending", id_);
                break;
            }

            // 复用已分配的 vector 内存，仅 resize 调整大小
            data.resize(read_size_);
            const auto n = co_await target_->async_read_some(data, ec);
            if (ec || n == 0)
            {
                if (ec != std::errc::operation_canceled && fault::to_code(ec) != fault::code::eof)
                {
                    trace::debug<flt::conn | flt::protocol>("stream {} read from target failed: {}", id_, ec.message());
                }
                break;
            }
            data.resize(n);
            read_bytes_.fetch_add(n, std::memory_order_relaxed);

            // 检查 mux 会话是否仍活跃
            auto owner = owner_.lock();
            if (!owner || !owner->is_active())
            {
                break;
            }

            co_await owner->send_data(id_, std::move(data));
        }

        // 标记 target 端已关闭
        target_closed_.store(true, std::memory_order_release);

        // 如果 mux 端未关闭且会话仍活跃，通知 mux 关闭
        if (!mux_closed_.load(std::memory_order_acquire))
        {
            if (auto owner = owner_.lock(); owner && owner->is_active())
            {
                owner->send_fin(id_);
            }
        }
    }


    // target 写循环（客户端上行/上传方向）
    // 从 write_channel_ 取数据写入 target。
    // write_channel_ 解耦帧循环与 target 写入，避免慢速 target 阻塞帧循环。
    auto duct::target_writeloop()
        -> net::awaitable<void>
    {
        while (!closed_)
        {
            boost::system::error_code ch_ec;
            auto token = net::redirect_error(trace::use_prefix_awaitable, ch_ec);
            auto data = co_await write_channel_.async_receive(token);
            if (ch_ec)
            {
                // 通道关闭或取消，正常退出
                break;
            }

            std::error_code write_ec;
            co_await transport::async_write(*target_, data, write_ec);
            if (write_ec)
            {
                trace::debug<flt::conn | flt::protocol>("stream {} write to target failed: {}", id_, write_ec.message());
                close();
                break;
            }
            written_bytes_.fetch_add(data.size(), std::memory_order_relaxed);
        }
    }

} // namespace psm::multiplex
