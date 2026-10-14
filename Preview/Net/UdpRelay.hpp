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
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <system_error>
#include <utility>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <boost/system/system_error.hpp>

#include <Preview/Foundation/Error.hpp>
#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Udp/EndpointRetirement.hpp>
#include <Preview/Transport/Transmission.hpp>
#include <Preview/Transport/Unreliable.hpp>

namespace Preview::Network::Udp
{

    namespace Net = boost::asio;

    /**
     * @struct RelayOptions
     * @brief UDP 中继选项
     */
    struct RelayOptions
    {
        std::chrono::milliseconds IdleTimeout{std::chrono::seconds(60)}; ///< 会话空闲超时（0=禁用）
        std::size_t MaxAssociations{256}; ///< 最大并发关联数（0=不限）
    };

    /**
     * @class UdpRelay
     * @brief UDP 双向中继器（关联生命周期）
     * @details 关联表和回收 timer 由 Run 的当前 coroutine executor 驱动；本类不创建 strand，
     *          调用方须以串行执行域驱动 Run。NativeSocket 收发仍使用各端点固定的 socket executor；
     *          调用方须保持这些 executor 的 context 运行，并避免从外部并发修改端点。
     *          任一方向结束后组合协程取消并等待其余任务退出，再对两端提交 Cancel/Close 并等待
     *          两个 Activity::Drain。首个业务、取消、原生或退休失败以 typed 结果返回。
     *          UDP 不提供流式半关闭；socket 的 native I/O 由两端 Unreliable 管理。
     */
    class UdpRelay
    {
        struct AssocTable;

        struct RelayDirection final
        {
            std::shared_ptr<Preview::Transport::Unreliable> Source;
            std::shared_ptr<Preview::Transport::Unreliable> Destination;
            std::shared_ptr<AssocTable> Table;
            bool FromIsA{false};
        };

    public:
        /**
         * @brief 构造
         * @param EndpointA 端 A（Unreliable 包装）
         * @param EndpointB 端 B（Unreliable 包装）
         * @param Options 中继选项
         */
        UdpRelay(std::shared_ptr<Preview::Transport::Unreliable> EndpointA,
                  std::shared_ptr<Preview::Transport::Unreliable> EndpointB,
                  RelayOptions Options = {})
            : A_(std::move(EndpointA)), B_(std::move(EndpointB)), Opts_(Options)
        {
        }

        /**
         * @brief 运行双向 UDP 中继并等待两端退休。
         * @return 正常方向终止返回成功；取消、native I/O、控制交付或 drain 失败返回首个失败。
         * @note 在返回 awaitable 前复制端点和选项；中继协程不借用本对象。调用方 executor 须串行。
         */
        [[nodiscard]] auto Run()
            -> Net::awaitable<std::expected<void, Preview::Fault::Failure>>
        {
            return RunOwned(A_, B_, Opts_);
        }

    private:
        /**
         * @struct AssocTable
         * @brief 会话关联表（A 端点 ↔ B 端点配对 + 超时时间）
         */
        struct AssocTable
        {
            AssocTable(std::chrono::milliseconds IdleTimeout, std::size_t MaxAssociations)
                : Timeout_(IdleTimeout), MaxAssociations_(MaxAssociations)
            {
            }

            /// 单侧条目：配对端点 + 最后活动时刻
            struct Entry
            {
                Net::ip::udp::endpoint Peer{}; ///< 对端（配对端点）
                std::uint64_t LastSeen{0};    ///< 最后活动（毫秒）
            };

            /**
             * @brief 查询来源配对目标
             * @param SourceEndpoint 来源端点
             * @param FromA 来源是否 A 侧
             * @return 配对目标（未配对返回 nullopt）
             */
            [[nodiscard]] auto PeerOf(const Net::ip::udp::endpoint &SourceEndpoint, bool FromA) const
                -> std::optional<Net::ip::udp::endpoint>
            {
                const auto &Table = [&]() -> const decltype(AToB_) & {
                    if (FromA)
                    {
                        return AToB_;
                    }
                    return BToA_;
                }();
                const auto It = Table.find(SourceEndpoint);
                if (It == Table.end() || It->second.Peer == Net::ip::udp::endpoint{})
                {
                    return std::nullopt; // 未学习或未配对
                }
                return It->second.Peer;
            }

            /**
             * @brief 关联/配对：记录来源，与对侧未配对来源配对，刷新活动时间
             * @param SourceEndpoint 来源端点（本侧）
             * @param FromA 来源是否 A 侧
             */
            void Touch(const Net::ip::udp::endpoint &SourceEndpoint, bool FromA)
            {
                auto &Self = [&]() -> decltype(AToB_) & {
                    if (FromA)
                    {
                        return AToB_;
                    }
                    return BToA_;
                }();
                auto &Other = [&]() -> decltype(AToB_) & {
                    if (FromA)
                    {
                        return BToA_;
                    }
                    return AToB_;
                }();
                const auto Now = NowMs();
                auto It = Self.find(SourceEndpoint);
                if (It == Self.end())
                {
                    // 新来源：移除本侧旧的未配对条目（单活跃会话简化）
                    for (auto I = Self.begin(); I != Self.end();)
                    {
                        if (I->second.Peer == Net::ip::udp::endpoint{})
                        {
                            I = Self.erase(I);
                        }
                        else
                        {
                            ++I;
                        }
                    }
                    It = Self.emplace(SourceEndpoint, Entry{{}, Now}).first;
                }
                else
                {
                    It->second.LastSeen = Now;
                }
                if (It->second.Peer != Net::ip::udp::endpoint{})
                {
                    return; // 已配对
                }
                // 与对侧最新的未配对来源配对；过期候选直接回收，避免新来源
                // 与陈旧端点配对造成跨会话流量混淆。
                std::optional<Net::ip::udp::endpoint> Best;
                std::uint64_t BestSeen = 0;
                for (auto I = Other.begin(); I != Other.end();)
                {
                    if (I->second.Peer != Net::ip::udp::endpoint{})
                    {
                        ++I;
                        continue;
                    }
                    if (Timeout_.count() > 0 &&
                        Now - I->second.LastSeen > static_cast<std::uint64_t>(Timeout_.count()))
                    {
                        I = Other.erase(I);
                        continue;
                    }
                    if (!Best || I->second.LastSeen > BestSeen)
                    {
                        Best = I->first;
                        BestSeen = I->second.LastSeen;
                    }
                    ++I;
                }
                if (!Best)
                {
                    return; // 无可用候选：等对侧来源
                }
                if (MaxAssociations_ != 0 && PairedCount_ >= MaxAssociations_)
                {
                    // 达到关联上限：拒绝新会话，丢弃两侧未配对占位
                    Other.erase(*Best);
                    Self.erase(It);
                    return;
                }
                It->second.Peer = *Best;
                Other[*Best].Peer = SourceEndpoint;
                ++PairedCount_;
            }

            /**
             * @brief 对称回收超时条目
             * @return 回收条目数
             * @details 未配对条目按自身时间回收；配对条目按两侧最后活动的
             *          较大值判定空闲，并同时移除两侧映射。仅扫描单侧会
             *          让先到且长期未配对的另一侧条目永久残留。
             */
            auto Reap() -> std::size_t
            {
                if (Timeout_.count() <= 0)
                {
                    return 0;
                }
                const auto Now = NowMs();
                const auto Limit = static_cast<std::uint64_t>(Timeout_.count());
                const auto Idle = [&](const std::uint64_t Last) { return Now - Last > Limit; };
                std::size_t Removed = 0;
                // A 侧：未配对按自身时间；配对按两侧最大值
                for (auto It = AToB_.begin(); It != AToB_.end();)
                {
                    auto &Slot = It->second;
                    if (Slot.Peer == Net::ip::udp::endpoint{})
                    {
                        if (Idle(Slot.LastSeen))
                        {
                            It = AToB_.erase(It);
                            ++Removed;
                        }
                        else
                        {
                            ++It;
                        }
                        continue;
                    }
                    const auto PeerIt = BToA_.find(Slot.Peer);
                    if (PeerIt == BToA_.end() || Idle(std::max(Slot.LastSeen, PeerIt->second.LastSeen)))
                    {
                        if (PeerIt != BToA_.end())
                        {
                            BToA_.erase(PeerIt);
                        }
                        It = AToB_.erase(It);
                        if (PairedCount_ > 0)
                        {
                            --PairedCount_;
                        }
                        ++Removed;
                        continue;
                    }
                    ++It;
                }
                // B 侧：未配对同样回收；配对残项（A 侧缺失/已超时）清理
                for (auto It = BToA_.begin(); It != BToA_.end();)
                {
                    auto &Slot = It->second;
                    if (Slot.Peer == Net::ip::udp::endpoint{})
                    {
                        if (Idle(Slot.LastSeen))
                        {
                            It = BToA_.erase(It);
                            ++Removed;
                        }
                        else
                        {
                            ++It;
                        }
                        continue;
                    }
                    const auto PeerIt = AToB_.find(Slot.Peer);
                    if (PeerIt == AToB_.end() || Idle(std::max(Slot.LastSeen, PeerIt->second.LastSeen)))
                    {
                        if (PeerIt != AToB_.end())
                        {
                            AToB_.erase(PeerIt);
                        }
                        It = BToA_.erase(It);
                        if (PairedCount_ > 0)
                        {
                            --PairedCount_;
                        }
                        ++Removed;
                        continue;
                    }
                    ++It;
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

            std::chrono::milliseconds Timeout_{std::chrono::seconds(60)}; ///< 空闲超时（0 = 禁用）
            std::size_t MaxAssociations_{256};                            ///< 最大并发关联（0 = 不限）
            std::size_t PairedCount_{0};                                  ///< 当前已配对关联数
            std::map<Net::ip::udp::endpoint, Entry> AToB_; ///< A 来源 → 配对
            std::map<Net::ip::udp::endpoint, Entry> BToA_; ///< B 来源 → 配对
        };

        using RelayResult = Detail::RelayResult;

        /** @brief 竞速两个方向，并在返回前等待被取消方向真实退出。 */
        [[nodiscard]] static auto RunDirections(
            std::shared_ptr<Preview::Transport::Unreliable> EndpointA,
            std::shared_ptr<Preview::Transport::Unreliable> EndpointB,
            std::shared_ptr<AssocTable> Assoc) -> Net::awaitable<RelayResult>
        {
            using Net::experimental::awaitable_operators::operator||;
            auto Outcome = co_await (
                RelayOne(RelayDirection{EndpointA, EndpointB, Assoc, true}) ||
                RelayOne(RelayDirection{EndpointB, EndpointA, std::move(Assoc), false}));
            if (Outcome.index() == 0U)
            {
                co_return std::move(std::get<0>(Outcome));
            }
            co_return std::move(std::get<1>(Outcome));
        }

        [[nodiscard]] static auto RunOwned(
            std::shared_ptr<Preview::Transport::Unreliable> EndpointA,
            std::shared_ptr<Preview::Transport::Unreliable> EndpointB,
            RelayOptions Options) -> Net::awaitable<RelayResult>
        {
            using Net::experimental::awaitable_operators::operator||;
            Detail::EndpointRetirement Retirement(EndpointA, EndpointB);
            Preview::Fault::Failure Primary;
            std::exception_ptr FatalException;
            if (!EndpointA || !EndpointB)
            {
                Primary = {Preview::Fault::Code::InvalidArgument};
            }
            else
            {
                try
                {
                    auto Assoc = std::make_shared<AssocTable>(
                        Options.IdleTimeout, Options.MaxAssociations);
                    RelayResult RunResult;
                    if (Options.IdleTimeout.count() <= 0)
                    {
                        RunResult = co_await RunDirections(EndpointA, EndpointB, Assoc);
                    }
                    else
                    {
                        auto Outcome = co_await (
                            RunDirections(EndpointA, EndpointB, Assoc) ||
                            RecycleLoop(Assoc, Options.IdleTimeout));
                        if (Outcome.index() == 0U)
                        {
                            RunResult = std::move(std::get<0>(Outcome));
                        }
                        else
                        {
                            RunResult = std::move(std::get<1>(Outcome));
                        }
                    }
                    if (!RunResult)
                    {
                        Primary = RunResult.error();
                    }
                }
                catch (const boost::system::system_error &NativeError)
                {
                    Primary = Preview::Fault::FromNative(
                        static_cast<std::error_code>(NativeError.code()));
                }
                catch (const std::system_error &NativeError)
                {
                    Primary = Preview::Fault::FromNative(NativeError.code());
                }
                catch (...)
                {
                    FatalException = std::current_exception();
                }
            }
            co_return co_await Retirement.Finish(
                std::move(Primary), std::move(FatalException));
        }

        /**
         * @brief 按值拥有一条 UDP 方向的接收、配对和发送协程。
         * @param Direction 两端 socket、关联表和来源侧身份；均由协程帧持有。
         * @return 端点读写失败、取消或关闭后完成；未配对首包仍按原规则丢弃。
         * @note 不改变 UDP endpoint 学习、半关闭或 peer close 语义。
         */
        [[nodiscard]] static auto RelayOne(RelayDirection Direction)
            -> Net::awaitable<RelayResult>
        {
            auto &Source = *Direction.Source;
            auto &Destination = *Direction.Destination;
            auto Table = std::move(Direction.Table);
            const auto FromIsA = Direction.FromIsA;
            // 64KB 缓冲由该方向协程独占，避免两方向读写竞争。
            auto Buf = std::make_shared<std::array<std::byte, 65535>>();
            while (true)
            {
                Net::ip::udp::endpoint SourceEndpoint;
                boost::system::error_code ReceiveError;
                const auto N = co_await Source.NativeSocket().async_receive_from(
                    Net::buffer(Buf->data(), Buf->size()), SourceEndpoint,
                    Net::redirect_error(Net::use_awaitable, ReceiveError));
                if (ReceiveError)
                {
                    co_return std::unexpected(Preview::Fault::FromNative(
                        static_cast<std::error_code>(ReceiveError)));
                }
                if (N == 0)
                {
                    co_return RelayResult{};
                }
                Table->Touch(SourceEndpoint, FromIsA);
                const auto Peer = Table->PeerOf(SourceEndpoint, FromIsA);
                if (!Peer)
                {
                    continue;
                }
                boost::system::error_code WriteError;
                (void)co_await Destination.NativeSocket().async_send_to(
                    Net::buffer(Buf->data(), N), *Peer,
                    Net::redirect_error(Net::use_awaitable, WriteError));
                if (WriteError)
                {
                    co_return std::unexpected(Preview::Fault::FromNative(
                        static_cast<std::error_code>(WriteError)));
                }
                Table->Touch(SourceEndpoint, FromIsA);
            }
            co_return RelayResult{};
        }

        /**
         * @brief 会话回收循环：周期扫描超时会话
         * @param Table 关联表
         */
        [[nodiscard]] static auto RecycleLoop(
            std::shared_ptr<AssocTable> Table,
            std::chrono::milliseconds IdleTimeout) -> Net::awaitable<RelayResult>
        {
            while (true)
            {
                Net::steady_timer Timer(co_await Net::this_coro::executor);
                Timer.expires_after(IdleTimeout);
                boost::system::error_code ErrorCode;
                co_await Timer.async_wait(Net::redirect_error(Net::use_awaitable, ErrorCode));
                if (ErrorCode == Net::error::operation_aborted)
                {
                    co_return std::unexpected(Preview::Fault::FromNative(
                        static_cast<std::error_code>(ErrorCode)));
                }
                if (ErrorCode)
                {
                    co_return std::unexpected(Preview::Fault::FromNative(
                        static_cast<std::error_code>(ErrorCode)));
                }
                Table->Reap();
            }
            co_return RelayResult{};
        }

        std::shared_ptr<Preview::Transport::Unreliable> A_; ///< 端 A
        std::shared_ptr<Preview::Transport::Unreliable> B_; ///< 端 B
        RelayOptions Opts_;                               ///< 中继选项
    };

} // namespace Preview::Network::Udp
