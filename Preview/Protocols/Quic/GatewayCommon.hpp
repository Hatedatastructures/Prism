/**
 * @file GatewayCommon.hpp
 * @brief QUIC 网关公共骨架（连接绑定 + 连接表）
 * @details QUIC 连接在登记时绑定 ALPN/协议，后续数据流只使用该绑定，
 *          不从每条流的首字节重新猜测协议。
 * 与生产实现 src/prism/runtime/front/quic_gateway.cpp 的
 * 连接状态语义对齐，本文件提供测试可注入的骨架：
 * - GatewayCommon：连接表（ConnKey → 连接状态）+ 分发钩子，
 *   子类重写 OnH3Stream / OnTuicStream 实现具体协议接入
 * @note 仅骨架，不依赖 ngtcp2/nghttp3，测试可独立编译。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include <Preview/Foundation/Error.hpp>

namespace Preview::Quic
{

    /**
     * @enum ConnectionProtocol
     * @brief QUIC 连接级上层协议绑定
     */
    enum class ConnectionProtocol : std::uint8_t
    {
        Unknown,
        H3,
        Hysteria2 = H3,
        Tuic,
    };

    /**
     * @enum ConnectionLifecycle
     * @brief QUIC 连接的数据面生命周期
     * @details Draining 状态拒绝新 stream，但允许调用方先完成显式关闭。
     */
    enum class ConnectionLifecycle : std::uint8_t
    {
        Active,
        Draining,
    };

    /// 兼容旧名称；新代码应使用 ConnectionProtocol
    using ProtocolGuess = ConnectionProtocol;

    /**
     * @brief 保留的兼容接口；QUIC stream 不再按首字节猜测
     * @param FirstBytes 流首字节
     * @return 始终返回 Unknown
     */
    [[nodiscard]] inline auto GuessProtocol(std::span<const std::byte> FirstBytes) noexcept
        -> ProtocolGuess
    {
        (void)FirstBytes;
        return ProtocolGuess::Unknown;
    }

    /**
     * @struct ConnectionState
     * @brief QUIC 连接状态（连接表条目）
     * @details 记录单条 QUIC 连接的协议判定与认证进度，
     * 后续可扩展速率、活跃流计数等字段。
     */
    struct ConnectionState
    {
        ConnectionProtocol Type{ConnectionProtocol::Unknown}; ///< 连接绑定协议
        std::string Alpn;                             ///< 连接绑定 ALPN
        std::uint64_t PeerSource{0};                  ///< 最近接受的数据源标识
        bool authenticated{false};                    ///< 是否认证通过（保留兼容字段）
        std::uint64_t StreamCount{0};                ///< 已分发数据流数
        ConnectionLifecycle Lifecycle{ConnectionLifecycle::Active}; ///< 连接生命周期
    };

    /**
     * @class GatewayCommon
     * @brief QUIC 网关公共骨架
     * @details 维护连接表（ConnKey → ConnectionState），
     * 提供统一的分发入口 Dispatch()：按连接绑定协议
     * 转发到对应虚钩子。子类重写 OnH3Stream / OnTuicStream
     * 接入具体协议处理；默认实现为空操作。
     * @note 单线程使用（io_context 线程），无需加锁。
     */
    class GatewayCommon
    {
    public:
        /// 连接键（对端端点哈希，对齐生产 ConnKey 语义）
        using ConnKey = std::uint64_t;

        virtual ~GatewayCommon() = default;

        GatewayCommon() = default;
        GatewayCommon(const GatewayCommon &) = delete;
        auto operator=(const GatewayCommon &) -> GatewayCommon & = delete;

        /**
         * @brief 登记新连接
         * @param Key 连接键
         * @return 是否新增成功（已存在返回 false）
         */
        [[nodiscard]] auto RegisterConnection(
            ConnKey Key,
            ConnectionProtocol Protocol,
            std::string_view Alpn = {},
            std::uint64_t PeerSource = 0) -> bool
        {
            ConnectionState State;
            State.Type = Protocol;
            State.Alpn = Alpn;
            State.PeerSource = PeerSource;
            const auto Inserted = Conns_.emplace(Key, std::move(State)).second;
            if (Inserted)
            {
                ConnectionGenerations_[Key] = NextConnectionGeneration_++;
            }
            return Inserted;
        }

        [[nodiscard]] auto RegisterConnection(ConnKey Key) -> bool
        {
            return RegisterConnection(Key, ConnectionProtocol::Unknown);
        }

        /**
         * @brief 登记经过完整校验的 typed QUIC 连接
         * @param Key 连接键
         * @param Protocol 连接级协议
         * @param Alpn 已协商的 ALPN
         * @param PeerSource 当前对端来源标识
         * @return 明确的登记结果
         * @details 旧 RegisterConnection 保留给纯连接表测试；真实 front
         *          必须使用该入口，避免 Unknown/空 ALPN/空 source 进入数据面。
         */
        [[nodiscard]] auto RegisterTypedConnection(
            ConnKey Key,
            ConnectionProtocol Protocol,
            std::string_view Alpn,
            std::uint64_t PeerSource) -> Preview::Error
        {
            if (Key == 0 || Protocol == ConnectionProtocol::Unknown || Alpn.empty())
            {
                return Preview::Error::BadMessage;
            }
            if (PeerSource == 0)
            {
                return Preview::Error::BadAddress;
            }
            if (!RegisterConnection(Key, Protocol, Alpn, PeerSource))
            {
                return Preview::Error::ProtocolError;
            }
            if (auto *State = Lookup(Key))
            {
                State->authenticated = true;
            }
            return Preview::Error::None;
        }

        /**
         * @brief 移除连接
         * @param Key 连接键
         * @return 是否存在并移除
         */
        auto EraseConnection(ConnKey Key) -> bool
        {
            const auto Erased = Conns_.erase(Key) != 0;
            if (Erased)
            {
                ConnectionGenerations_.erase(Key);
            }
            return Erased;
        }

        /**
         * @brief 停止接受指定连接的新数据流
         * @param Key 连接键
         * @return 成功进入或已处于 drain 返回 None
         */
        [[nodiscard]] auto BeginDrain(ConnKey Key) -> Preview::Error
        {
            auto *State = Lookup(Key);
            if (!State)
            {
                return Preview::Error::NotOpen;
            }
            State->Lifecycle = ConnectionLifecycle::Draining;
            return Preview::Error::None;
        }

        /**
         * @brief 查询连接是否已经停止接收新数据流
         */
        [[nodiscard]] auto IsDraining(ConnKey Key) const noexcept -> bool
        {
            const auto *State = Lookup(Key);
            return State && State->Lifecycle == ConnectionLifecycle::Draining;
        }

        /**
         * @brief 查询连接状态
         * @param Key 连接键
         * @return 状态指针；不存在返回 nullptr
         */
        [[nodiscard]] auto Lookup(ConnKey Key) noexcept -> ConnectionState *
        {
            const auto Iterator = Conns_.find(Key);
            if (Iterator == Conns_.end())
            {
                return nullptr;
            }
            return &Iterator->second;
        }

        /**
         * @brief 查询连接状态（只读）
         * @param Key 连接键
         * @return 状态指针；不存在返回 nullptr
         */
        [[nodiscard]] auto Lookup(ConnKey Key) const noexcept -> const ConnectionState *
        {
            const auto Iterator = Conns_.find(Key);
            if (Iterator == Conns_.end())
            {
                return nullptr;
            }
            return &Iterator->second;
        }

        /**
         * @brief 连接表大小
         * @return 活跃连接数
         */
        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Conns_.size();
        }

        /**
         * @brief 按连接绑定分发新数据流
         * @param Key 连接键
         * @param FirstBytes 流数据前缀（仅作为回调数据，不用于协议猜测）
         * @return 是否成功分发给已绑定协议
         */
        auto Dispatch(ConnKey Key, std::span<const std::byte> FirstBytes) -> bool
        {
            return DispatchTyped(Key, FirstBytes) == Preview::Error::None;
        }

        /**
         * @brief 按连接绑定分发并返回 typed 拒绝原因
         * @param Key 连接键
         * @param FirstBytes 流数据前缀
         * @return 成功或明确的连接/协议错误
         */
        [[nodiscard]] auto DispatchTyped(
            ConnKey Key,
            std::span<const std::byte> FirstBytes) -> Preview::Error
        {
            return DispatchBoundTyped(Key, FirstBytes);
        }

        /**
         * @brief 校验 source 并按连接绑定分发数据流
         * @param Key 连接键
         * @param Source 数据源标识；非零值可表示 NAT rebinding 后的新来源
         * @param FirstBytes 流数据前缀
         * @return source 合法且连接已绑定时返回 true
         */
        auto Dispatch(
            ConnKey Key,
            std::uint64_t Source,
            std::span<const std::byte> FirstBytes) -> bool
        {
            return DispatchTyped(Key, Source, FirstBytes) == Preview::Error::None;
        }

        [[nodiscard]] auto DispatchTyped(
            ConnKey Key,
            std::uint64_t Source,
            std::span<const std::byte> FirstBytes) -> Preview::Error
        {
            auto *State = Lookup(Key);
            if (!State)
            {
                return Preview::Error::NotOpen;
            }
            if (State->Lifecycle != ConnectionLifecycle::Active)
            {
                return Preview::Error::Canceled;
            }
            if (Source == 0)
            {
                return Preview::Error::BadAddress;
            }
            State->PeerSource = Source;
            return DispatchBoundTyped(Key, FirstBytes);
        }

    protected:
        auto DispatchBound(ConnKey Key, std::span<const std::byte> FirstBytes) -> bool
        {
            return DispatchBoundTyped(Key, FirstBytes) == Preview::Error::None;
        }

        [[nodiscard]] auto DispatchBoundTyped(
            ConnKey Key,
            std::span<const std::byte> FirstBytes) -> Preview::Error
        {
            auto *State = Lookup(Key);
            if (!State)
            {
                return Preview::Error::NotOpen;
            }
            if (State->Lifecycle != ConnectionLifecycle::Active)
            {
                return Preview::Error::Canceled;
            }
            const auto GenerationIterator = ConnectionGenerations_.find(Key);
            if (GenerationIterator == ConnectionGenerations_.end())
            {
                return Preview::Error::ProtocolError;
            }
            const auto Protocol = State->Type;
            const auto Generation = GenerationIterator->second;
            switch (Protocol)
            {
            case ConnectionProtocol::H3:
                OnH3Stream(Key, FirstBytes);
                if (auto *CurrentState = LookupCurrent(Key, Protocol, Generation))
                {
                    ++CurrentState->StreamCount;
                }
                return Preview::Error::None;
            case ConnectionProtocol::Tuic:
                OnTuicStream(Key, FirstBytes);
                if (auto *CurrentState = LookupCurrent(Key, Protocol, Generation))
                {
                    ++CurrentState->StreamCount;
                }
                return Preview::Error::None;
            default:
                return Preview::Error::NotSupported;
            }
        }

        /**
         * @brief hysteria2 流分发钩子（默认空操作）
         * @param Key 连接键
         * @param FirstBytes 流首字节
         * @details 子类重写：将流接入 nghttp3 认证流程。
         */
        virtual auto OnH3Stream(ConnKey Key, std::span<const std::byte> FirstBytes) -> void
        {
            (void)Key;
            (void)FirstBytes;
        }

        /**
         * @brief tuic 流分发钩子（默认空操作）
         * @param Key 连接键
         * @param FirstBytes 流首字节
         * @details 子类重写：将流接入 tuic 认证/数据流程。
         */
        virtual auto OnTuicStream(ConnKey Key, std::span<const std::byte> FirstBytes) -> void
        {
            (void)Key;
            (void)FirstBytes;
        }

    private:
        [[nodiscard]] auto LookupCurrent(
            ConnKey Key,
            ConnectionProtocol Protocol,
            std::uint64_t Generation) noexcept -> ConnectionState *
        {
            const auto GenerationIterator = ConnectionGenerations_.find(Key);
            if (GenerationIterator == ConnectionGenerations_.end() ||
                GenerationIterator->second != Generation)
            {
                return nullptr;
            }
            auto *State = Lookup(Key);
            if (!State || State->Type != Protocol)
            {
                return nullptr;
            }
            return State;
        }

        std::uint64_t NextConnectionGeneration_{1}; ///< 连接代次分配器
        std::unordered_map<ConnKey, std::uint64_t> ConnectionGenerations_; ///< 活跃连接代次
        std::unordered_map<ConnKey, ConnectionState> Conns_; ///< 连接表
    };

} // namespace Preview::Quic
