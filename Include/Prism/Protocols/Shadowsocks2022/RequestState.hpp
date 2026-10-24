/**
 * @file RequestState.hpp
 * @brief Shadowsocks 2022 请求增量 Serializer/Parser 状态机。
 * @details Serializer 负责生成完整首包，Parser 负责跨多次 Put 调用
 *          解密并解析固定头、变长头和初始载荷。无状态 wire helper
 *          位于 RequestWire.hpp。
 */

#pragma once

#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <system_error>
#include <vector>

namespace Prism::Shadowsocks2022
{

    /**
     * @brief SS2022 握手消息
     */
    struct Message
    {
        Address dst;
        std::string InitialPayload;
    };

    /**
     * @brief SS2022 握手序列化器
     */
    class Serializer
    {
    public:
        using RandomSource = std::function<int(std::uint8_t*, int)>;
        /**
         * @brief 构造
         * @param Psk 预共享密钥（16 字节）
         */
        explicit Serializer(const std::array<std::uint8_t, 16>& Psk, RandomSource Source = {});

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message& MessageValue, std::uint64_t TimeSec) -> void;

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码
         * @return 实际写入字节数
         */
        auto Get(boost::asio::mutable_buffer Buffer, std::error_code& ErrorCode) -> std::size_t;

        /**
         * @brief 是否已全部输出
         * @return true = 全部输出完毕
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return !Failed_ && Ready_ && Offset_ >= Wire_.size();
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        RandomSource Source_;
        std::vector<std::uint8_t> Wire_;
        std::size_t Offset_{0};
        bool Ready_{false};
        bool Failed_{false};
    };

    /**
     * @brief SS2022 握手解析器
     */
    class Parser
    {
    public:
        /**
         * @brief 构造解析器
         * @param Psk 预共享密钥（16 字节）
         */
        explicit Parser(const std::array<std::uint8_t, 16>& Psk);

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param ErrorCode 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(boost::asio::const_buffer Buffer, std::error_code& ErrorCode) -> std::size_t;

        /**
         * @brief 是否解析完成
         * @return true = 解析完成
         */
        [[nodiscard]] auto IsDone() const -> bool
        {
            return Done_;
        }

        /**
         * @brief 解析结果
         * @return 消息引用
         */
        [[nodiscard]] auto Get() const -> const Message&
        {
            return Msg_;
        }

        /**
         * @brief 获取握手固定头时间戳
         * @return 客户端握手时间戳（UTC 秒）
         */
        [[nodiscard]] auto TimeSec() const noexcept -> std::uint64_t
        {
            return TimeSec_;
        }

        /**
         * @brief 校验握手时间戳是否在允许窗口内
         * @param TimeWindow 允许的绝对误差（秒）
         * @return 时间戳有效返回 true
         */
        [[nodiscard]] auto IsTimestampFresh(std::uint64_t TimeWindow) const noexcept -> bool;

        /**
         * @brief 重置解析状态
         */
        auto Reset() -> void;

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        std::uint64_t TimeSec_{0};
        bool Done_{false};
    };

} // namespace Prism::Shadowsocks2022
