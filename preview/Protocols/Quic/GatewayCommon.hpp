/**
 * @file GatewayCommon.hpp
 * @brief QUIC 网关公共骨架（首字节分流 + 连接表）
 * @details QUIC 网关对未知协议流的分流逻辑：认证/数据流的首帧
 *          使用协议版本或帧类型做最小分流：
 *          0x01 = HTTP/3 HEADERS（hysteria2 认证）
 *          0x05 = TUIC v5 协议版本
 * 与生产实现 src/prism/runtime/front/quic_gateway.cpp 的
 * 分流逻辑对齐，本文件提供测试可注入的骨架：
 * - GuessProtocol：纯函数首字节判定，可单测
 * - GatewayCommon：连接表（ConnKey → 连接状态）+ 分发钩子，
 *   子类重写 OnH3Stream / OnTuicStream 实现具体协议接入
 * @note 仅骨架，不依赖 ngtcp2/nghttp3，测试可独立编译。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>

namespace Preview::Quic
{

    /**
     * @enum ProtocolGuess
     * @brief QUIC 上层协议猜测结果
     * @details 仅用于选择后续解析器；完整认证仍由对应协议状态机执行。
     * 不符合已知首帧契约的数据必须返回 Unknown。
     */
    enum class ProtocolGuess : std::uint8_t
    {
        Hysteria2, ///< Hysteria2（HTTP/3 认证）
        Tuic,      ///< TUIC v5
        Unknown,   ///< 无法判定
    };

    /**
     * @brief 按首字节猜测 QUIC 上层协议
     * @param FirstBytes 流的首字节（至少 1 字节）
     * @return 协议猜测结果
     * @details 分流规则：
     * - 0x01 = HTTP/3 HEADERS 帧 → hysteria2
     * - 0x05 = TUIC v5 版本字节 → tuic
     * - 其余 / 空输入 → unknown
     */
    [[nodiscard]] inline auto GuessProtocol(std::span<const std::byte> FirstBytes) noexcept
        -> ProtocolGuess
    {
        if (FirstBytes.empty())
        {
            return ProtocolGuess::Unknown;
        }
        const auto Fb = std::to_integer<std::uint8_t>(FirstBytes.front());
        // Hysteria2 认证首帧为 HTTP/3 HEADERS。
        if (Fb == 0x01)
        {
            return ProtocolGuess::Hysteria2;
        }
        // TUIC v5 消息首字节携带协议版本。
        if (Fb == 0x05)
        {
            return ProtocolGuess::Tuic;
        }
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
        ProtocolGuess Type{ProtocolGuess::Unknown}; ///< 已判定的协议类型
        bool authenticated{false};                    ///< 是否认证通过
        std::uint64_t StreamCount{0};                ///< 已分发数据流数
    };

    /**
     * @class GatewayCommon
     * @brief QUIC 网关公共骨架
     * @details 维护连接表（ConnKey → ConnectionState），
     * 提供统一的分发入口 Dispatch()：按首字节判定协议并
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
         * @param key 连接键
         * @return 是否新增成功（已存在返回 false）
         */
        [[nodiscard]] auto RegisterConnection(ConnKey key) -> bool
        {
            return Conns_.emplace(key, ConnectionState{}).second;
        }

        /**
         * @brief 移除连接
         * @param key 连接键
         * @return 是否存在并移除
         */
        auto EraseConnection(ConnKey key) -> bool
        {
            return Conns_.erase(key) != 0;
        }

        /**
         * @brief 查询连接状态
         * @param key 连接键
         * @return 状态指针；不存在返回 nullptr
         */
        [[nodiscard]] auto Lookup(ConnKey key) noexcept -> ConnectionState *
        {
            const auto It = Conns_.find(key);
            if (It == Conns_.end())
            {
                return nullptr;
            }
            return &It->second;
        }

        /**
         * @brief 查询连接状态（只读）
         * @param key 连接键
         * @return 状态指针；不存在返回 nullptr
         */
        [[nodiscard]] auto Lookup(ConnKey key) const noexcept -> const ConnectionState *
        {
            const auto It = Conns_.find(key);
            if (It == Conns_.end())
            {
                return nullptr;
            }
            return &It->second;
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
         * @brief 分发新数据流（首字节分流入口）
         * @param key 连接键
         * @param FirstBytes 流首字节（至少 1 字节）
         * @return 是否成功分发给已知协议（unknown 返回 false）
         * @details 判定成功后写入连接状态并调用对应虚钩子；
         * 未知协议返回 false 由调用方关闭连接。
         */
        auto Dispatch(ConnKey key, std::span<const std::byte> FirstBytes) -> bool
        {
            auto *State = Lookup(key);
            if (!State)
            {
                return false;
            }
            const auto Guess = GuessProtocol(FirstBytes);
            State->Type = Guess;
            switch (Guess)
            {
            case ProtocolGuess::Hysteria2:
                OnH3Stream(key, FirstBytes);
                return true;
            case ProtocolGuess::Tuic:
                OnTuicStream(key, FirstBytes);
                return true;
            default:
                return false;
            }
        }

    protected:
        /**
         * @brief hysteria2 流分发钩子（默认空操作）
         * @param key 连接键
         * @param FirstBytes 流首字节
         * @details 子类重写：将流接入 nghttp3 认证流程。
         */
        virtual auto OnH3Stream(ConnKey key, std::span<const std::byte> FirstBytes) -> void
        {
            (void)key;
            (void)FirstBytes;
        }

        /**
         * @brief tuic 流分发钩子（默认空操作）
         * @param key 连接键
         * @param FirstBytes 流首字节
         * @details 子类重写：将流接入 tuic 认证/数据流程。
         */
        virtual auto OnTuicStream(ConnKey key, std::span<const std::byte> FirstBytes) -> void
        {
            (void)key;
            (void)FirstBytes;
        }

    private:
        std::unordered_map<ConnKey, ConnectionState> Conns_; ///< 连接表
    };

} // namespace Preview::Quic
