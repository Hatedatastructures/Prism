#include <prism/protocol/multiplex/stream.hpp>

#include <prism/foundation/fault/handling.hpp>
#include <prism/net/transport/reliable.hpp>
#include <prism/diagnose/diagnose.hpp>

#include <boost/asio/co_spawn.hpp>

#include <atomic>
#include <span>

using namespace psm::diagnose;

namespace psm::multiplex
{

    namespace net = boost::asio;

    // 帧载荷最大长度（uint16_t 最大值，所有 mux 协议通用上限）
    constexpr std::size_t max_frame_payload = 65535;

    stream::stream(stream_options opts)
        : id_(opts.stream_id),
          egress_(std::move(opts.egress)),
          mr_(opts.mr),
          target_(std::move(opts.target)),
          prefix_(std::move(opts.prefix)),

          write_channel_(target_->executor(), 32)
    {
        // 限制读取大小不超过帧载荷上限，防止发送时 uint16_t 溢出
        read_size_ = std::min(opts.buffer_size, static_cast<std::uint32_t>(max_frame_payload));
    }


    stream::~stream() noexcept
    {
        close();
    }


    void stream::start()
    {
        auto self = shared_from_this();

        // target 读循环：target → mux → 客户端（下载方向）
        net::co_spawn(target_->executor(), target_readloop(),
            [self](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    diagnose::debug(self->prefix_, "stream {} target read loop error", self->id_);
                }
                self->close();
            });

        // target 写循环：客户端 → mux → target（上传方向），写错误自行关闭。
        // completion 捕获 self 保活：协程挂起期间 stream 可能被 control drop
        // 析构（如连接失败/超时），detached 不保活会 UAF 崩溃
        net::co_spawn(target_->executor(), target_writeloop(),
            [self](const std::exception_ptr &ep)
            {
                if (ep)
                {
                    diagnose::debug(self->prefix_, "stream {} target write loop error", self->id_);
                }
            });
    }


    auto stream::on_data(memory::vector<std::byte> data)
        -> net::awaitable<void>
    {
        diagnose::debug(prefix_, "[up] on_data stream={} {} bytes", id_, data.size());
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


    void stream::on_fin()
    {
        // mux 端半关闭，shutdown target 发送方向
        mux_closed_.store(true, std::memory_order_release);

        if (target_)
        {
            if (auto *rel = target_->lowest_layer<transport::reliable>())
            {
                rel->shutdown_write();
            }
            diagnose::debug(prefix_, "stream {} mux fin, shutdown target write", id_);
        }

        // target 端也已关闭，完全关闭管道
        if (target_closed_.load(std::memory_order_acquire))
        {
            close();
        }
    }


    void stream::close()
    {
        if (closed_)
        {
            return;
        }
        closed_ = true;

        // 关闭写通道，通知 target_writeloop 退出
        write_channel_.cancel();

        // 先关闭 target socket（取消所有 pending 异步操作），但不立即释放对象。
        // target_writeloop 可能正 co_await 在 async_write 上，completion handler
        // 需要 target 对象在 close() 返回后、handler 执行时仍然存活。
        if (target_)
        {
            target_->close();
        }

        if (auto ex = egress_.lock())
        {
            ex->drop(id_);
        }

        diagnose::debug(prefix_, "stream {} closed", id_);
    }


    // target 读循环（客户端下行/下载方向）
    // 从 target 读取数据，经 egress->send 回传会话层编码成帧发往客户端。
    auto stream::target_readloop()
        -> net::awaitable<void>
    {
        std::error_code ec;

        // 将 data 提到循环外，每次迭代仅 resize 复用已分配内存，避免重复分配
        memory::vector<std::byte> data(mr_);

        while (!closed_)
        {
            // mux 端已半关闭（客户端发送 FIN），停止发送数据
            if (mux_closed_.load(std::memory_order_acquire))
            {
                diagnose::debug(prefix_, "stream {} mux closed, stop sending", id_);
                break;
            }

            auto ex = egress_.lock();
            if (!ex || !ex->active())
            {
                break;
            }

            // 复用已分配的 vector 内存，仅 resize 调整大小
            data.resize(read_size_);
            const auto n = co_await target_->async_read_some(data, ec);
            if (ec || n == 0)
            {
                if (ec != std::errc::operation_canceled && fault::to_code(ec) != fault::code::eof)
                {
                    diagnose::debug(prefix_, "stream {} read from target failed: {}", id_, ec.message());
                }
                break;
            }
            data.resize(n);

            ex = egress_.lock();
            if (!ex || !ex->active())
            {
                break;
            }

            co_await ex->send(id_, std::move(data));
        }

        // 标记 target 端已关闭
        target_closed_.store(true, std::memory_order_release);

        // 如果 mux 端未关闭且会话仍活跃，通知 mux 关闭
        if (!mux_closed_.load(std::memory_order_acquire))
        {
            if (auto ex = egress_.lock(); ex && ex->active())
            {
                ex->fin(id_);
            }
        }
    }


    // target 写循环（客户端上行/上传方向）
    // 从 write_channel_ 取数据写入 target。
    // write_channel_ 解耦帧循环与 target 写入，避免慢速 target 阻塞帧循环。
    auto stream::target_writeloop()
        -> net::awaitable<void>
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

            diagnose::debug(prefix_, "[up] writeloop stream={} write {} bytes", id_, data.size());
            std::error_code write_ec;
            co_await transport::async_write(*target_, data, write_ec);
            if (write_ec)
            {
                diagnose::debug(prefix_, "stream {} write to target failed: {}", id_, write_ec.message());
                close();
                break;
            }
        }
    }

} // namespace psm::multiplex
