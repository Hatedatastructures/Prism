/**
 * @file UdpRelay.hpp
 * @brief UDP 双向中继（T3-4 D5 完整版）
 * @details 关联生命周期模型（Bind → 会话表 → 超时回收）：
 *          - 动态关联：A 侧首包学习来源 → 与 B 侧来源配对成会话
 *          - 会话表：{A 端点 ↔ B 端点} 双向映射，配对后双向转发
 *          - 超时回收：会话空闲超时后从表移除（后续包重新学习/丢弃）
 *          - 端口不匹配：未配对来源的包丢弃
 *          - 单侧关闭：任一端 socket 关闭 → 隧道结束
 * @note 真实语义（SOCKS5 UDP ASSOCIATE 动态客户端端口）：
 *       两端外部端点动态学习，无需预置 SetRemote
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <preview/Foundation/Error.hpp>
#include <preview/Transport/Transmission.hpp>
#include <preview/Transport/Unreliable.hpp>

namespace Preview::Network::Udp
{

    namespace net = boost::asio;

    /**
     * @struct RelayOptions
     * @brief UDP 中继选项
     */
    struct RelayOptions
    {
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)}; ///< 会话空闲超时（0=禁用）
    };

    /**
     * @class UdpRelay
     * @brief UDP 双向中继器（关联生命周期）
     * @details 并发转发两个方向；来源动态配对成会话；
     *          会话超时回收；单侧关闭终止。
     */
    class UdpRelay
    {
    public:
        /**
         * @brief 构造
         * @param a 端 A（Unreliable 包装）
         * @param b 端 B（Unreliable 包装）
         * @param opts 中继选项
         */
        UdpRelay(std::shared_ptr<Preview::Transport::Unreliable> a,
                  std::shared_ptr<Preview::Transport::Unreliable> b, RelayOptions opts = {})
            : A_(std::move(a)), B_(std::move(b)), Opts_(opts)
        {
        }

        /**
         * @brief 运行双向中继
         * @return 隧道结束后完成
         */
        [[nodiscard]] auto Run() -> net::awaitable<void>
        {
            using boost::asio::experimental::awaitable_operators::operator||;

            auto Assoc = std::make_shared<AssocTable>();

            // 单向转发：from 收 → 按会话表配对目标发 to
            auto RelayOne = [&](Preview::Transport::Unreliable &from,
                                 Preview::Transport::Unreliable &to,
                                 std::shared_ptr<AssocTable> Table,
                                 bool FromIsA) -> net::awaitable<void>
            {
                // 64KB 缓冲堆分配：协程帧只留 8 字节 shared_ptr（两方向各持独立缓冲，避免读写竞争）
                auto Buf = std::make_shared<std::array<std::byte, 65535>>();
                while (true)
                {
                    net::ip::udp::endpoint src;
                    boost::system::error_code REc;
                    const auto N = co_await from.NativeSocket().async_receive_from(
                        net::buffer(Buf->data(), Buf->size()), src,
                        net::redirect_error(net::use_awaitable, REc));
                    if (REc || N == 0)
                    {
                        co_return;
                    }
                    // 先学习/配对，再查转发目标（首包即配对）
                    Table->Touch(src, FromIsA);
                    const auto Peer = Table->PeerOf(src, FromIsA);
                    if (!Peer)
                    {
                        continue; // 未配对/已回收：丢弃
                    }
                    boost::system::error_code WEc;
                    co_await to.NativeSocket().async_send_to(
                        net::buffer(Buf->data(), N), *Peer,
                        net::redirect_error(net::use_awaitable, WEc));
                    if (WEc)
                    {
                        co_return;
                    }
                    Table->Touch(src, FromIsA);
                }
            };

            co_await (RelayOne(*A_, *B_, Assoc, true) ||
                      RelayOne(*B_, *A_, Assoc, false) || RecycleLoop(Assoc));
            A_->Close();
            B_->Close();
            co_return;
        }

    private:
        /**
         * @struct AssocTable
         * @brief 会话关联表（A 端点 ↔ B 端点配对 + 超时时间）
         */
        struct AssocTable
        {
            /// 单侧条目：配对端点 + 最后活动时刻
            struct Entry
            {
                net::ip::udp::endpoint Peer{}; ///< 对端（配对端点）
                std::uint64_t LastSeen{0};    ///< 最后活动（毫秒）
            };

            /**
             * @brief 查询来源配对目标
             * @param src 来源端点
             * @param FromA 来源是否 A 侧
             * @return 配对目标（未配对返回 nullopt）
             */
            [[nodiscard]] auto PeerOf(const net::ip::udp::endpoint &src, bool FromA) const
                -> std::optional<net::ip::udp::endpoint>
            {
                const auto &Table = [&]() -> const decltype(AToB_) & {
                    if (FromA)
                    {
                        return AToB_;
                    }
                    return BToA_;
                }();
                const auto It = Table.find(src);
                if (It == Table.end() || It->second.Peer == net::ip::udp::endpoint{})
                {
                    return std::nullopt; // 未学习或未配对
                }
                return It->second.Peer;
            }

            /**
             * @brief 关联/配对：记录来源，与对侧未配对来源配对，刷新活动时间
             * @param src 来源端点（本侧）
             * @param FromA 来源是否 A 侧
             */
            void Touch(const net::ip::udp::endpoint &src, bool FromA)
            {
                auto &self = [&]() -> decltype(AToB_) & {
                    if (FromA)
                    {
                        return AToB_;
                    }
                    return BToA_;
                }();
                auto &other = [&]() -> decltype(AToB_) & {
                    if (FromA)
                    {
                        return BToA_;
                    }
                    return AToB_;
                }();
                const auto Now = NowMs();
                auto It = self.find(src);
                if (It == self.end())
                {
                    // 新来源：移除本侧旧的未配对条目（单活跃会话简化）
                    for (auto I = self.begin(); I != self.end();)
                    {
                        if (I->second.Peer == net::ip::udp::endpoint{})
                        {
                            I = self.erase(I);
                        }
                        else
                        {
                            ++I;
                        }
                    }
                    It = self.emplace(src, Entry{{}, Now}).first;
                }
                else
                {
                    It->second.LastSeen = Now;
                }
                if (It->second.Peer != net::ip::udp::endpoint{})
                {
                    return; // 已配对
                }
                // 与对侧未配对来源配对（先到者等后到者）
                for (auto &[OtherSrc, oe] : other)
                {
                    if (oe.Peer == net::ip::udp::endpoint{})
                    {
                        It->second.Peer = OtherSrc;
                        oe.Peer = src;
                        return;
                    }
                }
            }

            /**
             * @brief 回收超时会话
             * @param timeout 超时（0 = 禁用）
             * @return 回收数
             */
            auto Reap(std::chrono::milliseconds timeout) -> std::size_t
            {
                if (timeout.count() <= 0)
                {
                    return 0;
                }
                const auto Now = NowMs();
                std::size_t Removed = 0;
                for (auto It = AToB_.begin(); It != AToB_.end();)
                {
                    if (Now - It->second.LastSeen >
                        static_cast<std::uint64_t>(timeout.count()))
                    {
                        BToA_.erase(It->second.Peer);
                        It = AToB_.erase(It);
                        ++Removed;
                    }
                    else
                    {
                        ++It;
                    }
                }
                return Removed;
            }

            [[nodiscard]] static auto NowMs() -> std::uint64_t
            {
                return static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch())
                        .count());
            }

            std::map<net::ip::udp::endpoint, Entry> AToB_; ///< A 来源 → 配对
            std::map<net::ip::udp::endpoint, Entry> BToA_; ///< B 来源 → 配对
        };

        /**
         * @brief 会话回收循环：周期扫描超时会话
         * @param Table 关联表
         */
        [[nodiscard]] auto RecycleLoop(std::shared_ptr<AssocTable> Table) -> net::awaitable<void>
        {
            if (Opts_.IdleTimeout.count() <= 0)
            {
                // 禁用回收：超长 timer 挂起（不占 socket 读，避免与转发竞争）
                net::steady_timer t(co_await net::this_coro::executor);
                t.expires_after(std::chrono::hours(24));
                boost::system::error_code ec;
                co_await t.async_wait(net::redirect_error(net::use_awaitable, ec));
                co_return;
            }
            while (true)
            {
                net::steady_timer t(co_await net::this_coro::executor);
                t.expires_after(Opts_.IdleTimeout);
                boost::system::error_code ec;
                co_await t.async_wait(net::redirect_error(net::use_awaitable, ec));
                if (ec == net::error::operation_aborted)
                {
                    // 组取消是一次性的：吞掉取消将使 || 组永不完成并泄漏 socket
                    co_return;
                }
                Table->Reap(Opts_.IdleTimeout);
            }
        }

        std::shared_ptr<Preview::Transport::Unreliable> A_; ///< 端 A
        std::shared_ptr<Preview::Transport::Unreliable> B_; ///< 端 B
        RelayOptions Opts_;                               ///< 中继选项
    };

} // namespace Preview::Network::Udp
