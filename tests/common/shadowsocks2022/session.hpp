/**
 * @file session.hpp
 * @brief SS2022 会话（连接级数据通道，满足 session_base）
 * @details 客户端/服务端握手后返回的会话对象：
 *          - 读：常驻解密协程读底层流 → chunk_codec 解密 → rx 队列
 *          - 写：chunk_codec 分块加密后发送
 * @note 会话由 shared_ptr 持有（enable_shared_from_this）。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/core/session_base.hpp>
#include <common/core/transport/transport_base.hpp>
#include <common/shadowsocks2022/chunk.hpp>
#include <common/shadowsocks2022/types.hpp>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <span>
#include <vector>

namespace psmtest::ss2022
{

    /// SS2022 会话选项
    struct session_options
    {
        /// 读超时（0 = 禁用）
        std::chrono::milliseconds timeout{0};
    };

    /// @brief SS2022 数据会话
    class session : public session_base, public std::enable_shared_from_this<session>
    {
    public:
        /// @brief 创建会话并启动解密协程
        /// @param raw 底层传输
        /// @param enc 发送侧编解码器（nonce 状态与握手衔接）
        /// @param dec 接收侧编解码器（nonce 状态与握手衔接）
        /// @param opt 会话选项
        /// @return 会话实例
        static auto create(std::shared_ptr<transport_base> raw,
                           chunk_codec enc, chunk_codec dec,
                           const session_options &opt = {}) -> std::shared_ptr<session>
        {
            auto self = std::shared_ptr<session>(
                new session(std::move(raw), std::move(enc), std::move(dec), opt));
            self->start();
            return self;
        }

        /// 读取解密后的明文
        auto read_some(std::span<std::uint8_t> buf) -> net::awaitable<std::size_t> override
        {
            using namespace boost::asio::experimental::awaitable_operators;

            while (true)
            {
                if (closed_ || canceled_)
                {
                    canceled_ = false;
                    co_return 0;
                }
                if (!rx_queue_.empty())
                {
                    const auto &front = rx_queue_.front();
                    const auto n = std::min(buf.size(), front.size());
                    std::memcpy(buf.data(), front.data(), n);
                    if (n < front.size())
                        rx_queue_.front().erase(rx_queue_.front().begin(),
                                                rx_queue_.front().begin() + static_cast<std::ptrdiff_t>(n));
                    else
                        rx_queue_.pop_front();
                    co_return n;
                }
                if (peer_eof_)
                    co_return 0;

                notify_.reset();
                if (opt_.timeout.count() > 0)
                {
                    timer_.expires_after(opt_.timeout);
                    auto result = co_await (notify_.async_receive(net::use_awaitable) ||
                                            timer_.async_wait(net::use_awaitable));
                    if (result.index() == 1)
                        co_return 0;
                }
                else
                {
                    co_await notify_.async_receive(net::use_awaitable);
                }
            }
        }

        /// 写入明文（分块加密后发送）
        auto write_all(std::span<const std::uint8_t> buf) -> net::awaitable<protocol_ec> override
        {
            if (closed_ || !raw_ || !raw_->is_open())
                co_return make_error_code(error::broken_pipe);
            const auto out = enc_.seal(buf);
            if (out.empty())
                co_return make_error_code(error::bad_length);
            co_await raw_->write_all(out);
            co_return boost::system::error_code{};
        }

        /// 半关：发送结束块
        auto shutdown() -> net::awaitable<void> override
        {
            if (raw_ && raw_->is_open())
            {
                const auto out = enc_.finish();
                co_await raw_->write_all(out);
                co_await raw_->shutdown();
            }
            co_return;
        }

        /// 关闭
        auto close() -> net::awaitable<void> override
        {
            closed_ = true;
            notify_.try_send(boost::system::error_code{});
            if (raw_)
                co_await raw_->close();
            co_return;
        }

        /// 取消挂起读
        auto cancel() -> void override
        {
            canceled_ = true;
            notify_.try_send(boost::system::error_code{});
        }

        /// 设置读超时
        auto set_timeout(std::chrono::milliseconds ms) -> void override
        {
            opt_.timeout = ms;
        }

        /// 流是否打开
        [[nodiscard]] auto is_open() const -> bool override
        {
            return !closed_ && raw_ && raw_->is_open();
        }

        /// 获取执行器
        [[nodiscard]] auto executor() const -> net::any_io_executor override
        {
            return ex_;
        }

        /// 内部：对端半关
        auto set_peer_eof() -> void
        {
            peer_eof_ = true;
            notify_.try_send(boost::system::error_code{});
        }

    private:
        /// @brief 构造（私有，经 create 创建）
        session(std::shared_ptr<transport_base> raw, chunk_codec enc, chunk_codec dec,
                const session_options &opt)
            : raw_(std::move(raw)), ex_(raw_->executor()), enc_(std::move(enc)),
              dec_(std::move(dec)), opt_(opt), notify_(ex_, 1), timer_(ex_)
        {
        }

        /// 启动解密协程
        auto start() -> void
        {
            auto self = this->shared_from_this();
            net::co_spawn(ex_, [self]() -> net::awaitable<void>
                          {
                co_await self->read_loop();
            }, net::detached);
        }

        /// 解密循环
        auto read_loop() -> net::awaitable<void>
        {
            while (raw_ && raw_->is_open() && !closed_)
            {
                // 读长度块（18 字节）
                std::array<std::uint8_t, len_block_size> head{};
                std::size_t done = 0;
                while (done < head.size())
                {
                    const auto n = co_await raw_->read_some(
                        std::span<std::uint8_t>(head.data() + done, head.size() - done));
                    if (n == 0)
                    {
                        set_peer_eof();
                        co_return;
                    }
                    done += n;
                }
                // 解密长度
                const auto len = dec_.open_len(head);
                if (!len)
                {
                    set_peer_eof();
                    co_return;
                }
                if (*len == 0) // 结束块
                {
                    set_peer_eof();
                    co_return;
                }
                // 读载荷块并解密
                std::vector<std::uint8_t> block(*len + aead_tag_len);
                done = 0;
                while (done < block.size())
                {
                    const auto n = co_await raw_->read_some(
                        std::span<std::uint8_t>(block.data() + done, block.size() - done));
                    if (n == 0)
                    {
                        set_peer_eof();
                        co_return;
                    }
                    done += n;
                }
                auto plain = dec_.open_payload(block);
                if (plain.empty())
                {
                    set_peer_eof();
                    co_return;
                }
                rx_queue_.push_back(std::move(plain));
                notify_.try_send(boost::system::error_code{});
            }
            set_peer_eof();
            co_return;
        }

        std::shared_ptr<transport_base> raw_;
        net::any_io_executor ex_;
        chunk_codec enc_;
        chunk_codec dec_;
        session_options opt_;
        boost::asio::experimental::channel<void(boost::system::error_code)> notify_;
        net::steady_timer timer_;
        std::deque<std::vector<std::uint8_t>> rx_queue_;
        bool peer_eof_{false};
        bool closed_{false};
        bool canceled_{false};
    };

} // namespace psmtest::ss2022
