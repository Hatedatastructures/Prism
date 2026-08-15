/**
 * @file gateway_common.hpp
 * @brief QUIC 网关公共骨架（首字节分流 + 连接表）
 * @details QUIC 网关对未知协议流的分流逻辑：QUIC 连接上
 * 的首个数据流（uni/bidi 均可）以首字节区分上层协议：
 *          0x04 = HTTP/3 SETTINGS 帧（hysteria2 认证）
 *          0x40 = tuic 协议（认证/数据帧）
 * 与生产实现 src/prism/runtime/front/quic_gateway.cpp 的
 * 分流逻辑对齐，本文件提供测试可注入的骨架：
 * - guess_protocol：纯函数首字节判定，可单测
 * - gateway_common：连接表（conn_key → 连接状态）+ 分发钩子，
 *   子类重写 on_h3_stream / on_tuic_stream 实现具体协议接入
 * @note 仅骨架，不依赖 ngtcp2/nghttp3，测试可独立编译。
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>

namespace psmtest::quic
{

    /**
     * @enum protocol_guess
     * @brief QUIC 上层协议猜测结果
     * @details 由首字节判定，可能误判的场景由后续认证流程
     * 兜底（判定失败直接关闭连接）。
     */
    enum class protocol_guess : std::uint8_t
    {
        hysteria2, ///< Hysteria2（HTTP/3 认证）
        tuic,      ///< TUIC v5
        unknown,   ///< 无法判定
    };

    /**
     * @brief 按首字节猜测 QUIC 上层协议
     * @param first_bytes 流的首字节（至少 1 字节）
     * @return 协议猜测结果
     * @details 分流规则（对齐生产 quic_gateway.cpp）：
     * - 0x04 = HTTP/3 SETTINGS 帧 → hysteria2
     * - 0x40 = tuic → tuic
     * - 其余 / 空输入 → unknown
     */
    [[nodiscard]] inline auto guess_protocol(std::span<const std::byte> first_bytes) noexcept
        -> protocol_guess
    {
        if (first_bytes.empty())
        {
            return protocol_guess::unknown;
        }
        const auto fb = std::to_integer<std::uint8_t>(first_bytes.front());
        if (fb == 0x04)
        {
            return protocol_guess::hysteria2;
        }
        if (fb == 0x40)
        {
            return protocol_guess::tuic;
        }
        return protocol_guess::unknown;
    }

    /**
     * @struct connection_state
     * @brief QUIC 连接状态（连接表条目）
     * @details 记录单条 QUIC 连接的协议判定与认证进度，
     * 后续可扩展速率、活跃流计数等字段。
     */
    struct connection_state
    {
        protocol_guess type{protocol_guess::unknown}; ///< 已判定的协议类型
        bool authenticated{false};                    ///< 是否认证通过
        std::uint64_t stream_count{0};                ///< 已分发数据流数
    };

    /**
     * @class gateway_common
     * @brief QUIC 网关公共骨架
     * @details 维护连接表（conn_key → connection_state），
     * 提供统一的分发入口 dispatch()：按首字节判定协议并
     * 转发到对应虚钩子。子类重写 on_h3_stream / on_tuic_stream
     * 接入具体协议处理；默认实现为空操作。
     * @note 单线程使用（io_context 线程），无需加锁。
     */
    class gateway_common
    {
    public:
        /// 连接键（对端端点哈希，对齐生产 conn_key 语义）
        using conn_key = std::uint64_t;

        virtual ~gateway_common() = default;

        gateway_common() = default;
        gateway_common(const gateway_common &) = delete;
        auto operator=(const gateway_common &) -> gateway_common & = delete;

        /**
         * @brief 登记新连接
         * @param key 连接键
         * @return 是否新增成功（已存在返回 false）
         */
        [[nodiscard]] auto register_connection(conn_key key) -> bool
        {
            return conns_.emplace(key, connection_state{}).second;
        }

        /**
         * @brief 移除连接
         * @param key 连接键
         * @return 是否存在并移除
         */
        auto erase_connection(conn_key key) -> bool
        {
            return conns_.erase(key) != 0;
        }

        /**
         * @brief 查询连接状态
         * @param key 连接键
         * @return 状态指针；不存在返回 nullptr
         */
        [[nodiscard]] auto lookup(conn_key key) noexcept -> connection_state *
        {
            const auto it = conns_.find(key);
            return it == conns_.end() ? nullptr : &it->second;
        }

        /**
         * @brief 查询连接状态（只读）
         * @param key 连接键
         * @return 状态指针；不存在返回 nullptr
         */
        [[nodiscard]] auto lookup(conn_key key) const noexcept -> const connection_state *
        {
            const auto it = conns_.find(key);
            return it == conns_.end() ? nullptr : &it->second;
        }

        /**
         * @brief 连接表大小
         * @return 活跃连接数
         */
        [[nodiscard]] auto size() const noexcept -> std::size_t
        {
            return conns_.size();
        }

        /**
         * @brief 分发新数据流（首字节分流入口）
         * @param key 连接键
         * @param first_bytes 流首字节（至少 1 字节）
         * @return 是否成功分发给已知协议（unknown 返回 false）
         * @details 判定成功后写入连接状态并调用对应虚钩子；
         * 未知协议返回 false 由调用方关闭连接。
         */
        auto dispatch(conn_key key, std::span<const std::byte> first_bytes) -> bool
        {
            auto *state = lookup(key);
            if (!state)
            {
                return false;
            }
            const auto guess = guess_protocol(first_bytes);
            state->type = guess;
            switch (guess)
            {
            case protocol_guess::hysteria2:
                on_h3_stream(key, first_bytes);
                return true;
            case protocol_guess::tuic:
                on_tuic_stream(key, first_bytes);
                return true;
            default:
                return false;
            }
        }

    protected:
        /**
         * @brief hysteria2 流分发钩子（默认空操作）
         * @param key 连接键
         * @param first_bytes 流首字节
         * @details 子类重写：将流接入 nghttp3 认证流程。
         */
        virtual auto on_h3_stream(conn_key key, std::span<const std::byte> first_bytes) -> void
        {
            (void)key;
            (void)first_bytes;
        }

        /**
         * @brief tuic 流分发钩子（默认空操作）
         * @param key 连接键
         * @param first_bytes 流首字节
         * @details 子类重写：将流接入 tuic 认证/数据流程。
         */
        virtual auto on_tuic_stream(conn_key key, std::span<const std::byte> first_bytes) -> void
        {
            (void)key;
            (void)first_bytes;
        }

    private:
        std::unordered_map<conn_key, connection_state> conns_; ///< 连接表
    };

} // namespace psmtest::quic
