/**
 * @file duct.cpp
 * @brief 多路复用 TCP 流管道实现
 * @details multiplex::duct 的双向转发实现。
 * target_read_loop：从 target 读取数据发送到 mux（客户端下行/下载）；
 * target_write_loop：从写通道取数据写入 target（客户端上行/上传）。
 * 写通道解耦帧循环与 target 写入，消除队头阻塞。
 */

#include <prism/multiplex/duct.hpp>
#include <prism/multiplex/core.hpp>
#include <prism/fault/handling.hpp>
#include <prism/trace.hpp>

#include <boost/asio/co_spawn.hpp>

constexpr std::string_view tag = "[Mux.Duct]";

namespace psm::multiplex
{
    namespace net = boost::asio;

    /// 帧载荷最大长度（uint16_t 最大值，所有 mux 协议通用上限）
    constexpr std::size_t max_frame_payload = 65535;

    duct::duct(const std::uint32_t stream_id, std::shared_ptr<core> owner,
               channel::transport::shared_transmission target,
               const std::uint32_t buffer_size, const memory::resource_pointer mr)
        : id_(stream_id), owner_(std::move(owner)), mr_(mr),
          target_(std::move(target)),
          write_channel_(target_->executor(), 32)
    {
        // 限制读取大小不超过帧载荷上限，防止 send_data 时 uint16_t 溢出
        read_size_ = std::min(buffer_size, static_cast<std::uint32_t>(max_frame_payload));
    }

    duct::~duct()
    {
        close();
    }

    void duct::start()
    {
        auto self = shared_from_this();

        // target 读循环：target → mux → 客户端（客户端下载方向）
        // 退出时关闭整个管道
        auto read_done = [self](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} target read loop error: {}", tag, self->id_, e.what());
                }
                catch (...)
                {
                    trace::error("{} stream {} target read loop unknown error", tag, self->id_);
                }
            }
            self->close();
        };
        net::co_spawn(target_->executor(), target_read_loop(), std::move(read_done));

        // target 写循环：客户端 → mux → write_channel_ → target（客户端上传方向）
        // 不触发 close，由 target_read_loop 退出或自身写错误触发
        auto write_done = [self](const std::exception_ptr &ep)
        {
            if (ep)
            {
                try
                {
                    std::rethrow_exception(ep);
                }
                catch (const std::exception &e)
                {
                    trace::debug("{} stream {} target write loop error: {}", tag, self->id_, e.what());
                }
                catch (...)
                {
                    trace::error("{} stream {} target write loop unknown error", tag, self->id_);
                }
            }
        };
        net::co_spawn(target_->executor(), target_write_loop(), std::move(write_done));
    }

    auto duct::on_mux_data(memory::vector<std::byte> data) -> net::awaitable<void>
    {
        if (closed_)
        {
            co_return;
        }

        boost::system::error_code ch_ec;
        auto token = net::redirect_error(net::use_awaitable, ch_ec);
        co_await write_channel_.async_send(boost::system::error_code{}, std::move(data), token);
        if (ch_ec)
        {
            // 通道已关闭或取消，静默退出
            co_return;
        }
    }

    void duct::on_mux_fin()
    {
        // mux 端半关闭，shutdown target 发送方向
        mux_closed_.store(true, std::memory_order_release);

        if (target_)
        {
            target_->shutdown_write();
            trace::debug("{} stream {} mux fin, shutdown target write", tag, id_);
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

        // 关闭写通道，通知 target_write_loop 退出
        write_channel_.cancel();

        if (target_)
        {
            target_->close();
            target_.reset();
        }

        try
        {
            owner_->remove_duct(id_);
        }
        catch (...)
        {
            trace::error("{} stream {} remove duct error", tag, id_);
        }

        trace::debug("{} stream {} closed", tag, id_);
    }

    /**
     * @brief target 读循环（客户端下行/下载方向）
     * @details 从 target 读取数据，通过 owner_->send_data 发回 mux 客户端。
     * 数据直接读入 PMR vector 并 move 传递，零额外拷贝。
     */
    auto duct::target_read_loop() -> net::awaitable<void>
    {
        std::error_code ec;

        while (!closed_)
        {
            // 直接读入 vector，PMR 池分配器复用同大小内存块，分配开销极低
            memory::vector<std::byte> data(mr_);
            data.resize(read_size_);
            const auto n = co_await target_->async_read_some(data, ec);
            if (ec || n == 0)
            {
                if (ec != std::errc::operation_canceled && fault::to_code(ec) != fault::code::eof)
                {
                    trace::debug("{} stream {} read from target failed: {}", tag, id_, ec.message());
                }
                break;
            }
            data.resize(n);

            // 检查 mux 会话是否仍活跃
            if (!owner_->is_active())
            {
                break;
            }

            co_await owner_->send_data(id_, std::move(data));
        }

        // 标记 target 端已关闭
        target_closed_.store(true, std::memory_order_release);

        // 如果 mux 端未关闭且会话仍活跃，通知 mux 关闭
        if (!mux_closed_.load(std::memory_order_acquire) && owner_->is_active())
        {
            owner_->send_fin(id_);
        }
    }

    /**
     * @brief target 写循环（客户端上行/上传方向）
     * @details 从 write_channel_ 取数据写入 target。
     * write_channel_ 解耦帧循环与 target 写入，避免慢速 target 阻塞帧循环。
     */
    auto duct::target_write_loop() -> net::awaitable<void>
    {
        while (!closed_)
        {
            boost::system::error_code ch_ec;
            auto token = net::redirect_error(net::use_awaitable, ch_ec);
            auto data = co_await write_channel_.async_receive(token);
            if (ch_ec)
            {
                // 通道关闭或取消，正常退出
                break;
            }

            std::error_code write_ec;
            co_await target_->async_write(data, write_ec);
            if (write_ec)
            {
                trace::debug("{} stream {} write to target failed: {}", tag, id_, write_ec.message());
                close();
                break;
            }
        }
    }

} // namespace psm::multiplex
