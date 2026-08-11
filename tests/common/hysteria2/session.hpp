/**
 * @file session.hpp
 * @brief Hysteria2 帧序列化器 / 解析器类（Beast 风格）
 * @details 借鉴 Boost.Beast serializer/parser 设计：
 *          - serializer：对象 → wire 字节（reset 后 get 增量输出）
 *          - parser：wire 字节 → 对象（put 增量喂入，is_done 完成）
 *          满足统一消息编解码接口，供测试与上层会话使用。
 * @note 参考 Boost.Beast http::serializer/parser 接口形状。
 */

#pragma once

#include <common/core/error.hpp>
#include <common/hysteria2/codec.hpp>
#include <common/hysteria2/types.hpp>

#include <boost/asio/buffer.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <system_error>
#include <vector>

namespace psmtest::hysteria2
{

    /// @brief Hysteria2 帧序列化器（对象 → wire）
    class serializer
    {
    public:
        /// @brief 重置并绑定消息
        /// @param msg 待序列化消息
        auto reset(const message &msg) -> void
        {
            if (msg.type == message::message::kind::udp)
                wire_ = build_udp(msg.session_id, msg.packet_id, msg.dst,
                                  std::span<const std::uint8_t>(
                                      reinterpret_cast<const std::uint8_t *>(msg.payload.data()),
                                      msg.payload.size()));
            else
                wire_ = build_tcp(msg.dst,
                                  std::span<const std::uint8_t>(
                                      reinterpret_cast<const std::uint8_t *>(msg.payload.data()),
                                      msg.payload.size()));
            offset_ = 0;
        }

        /// @brief 增量输出 wire 字节
        /// @param buffer 输出缓冲
        /// @param ec 输出错误码
        /// @return 本次写入字节数
        auto get(boost::asio::mutable_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto space = buffer.size();
            const auto remain = wire_.size() - offset_;
            const auto n = std::min(space, remain);
            std::memcpy(buffer.data(), wire_.data() + offset_, n);
            offset_ += n;
            return n;
        }

        /// 是否已全部输出
        [[nodiscard]] auto is_done() const -> bool
        {
            return offset_ >= wire_.size();
        }

        /// 剩余未输出字节数
        [[nodiscard]] auto remaining() const -> std::size_t
        {
            return wire_.size() - offset_;
        }

    private:
        std::vector<std::uint8_t> wire_;
        std::size_t offset_{0};
    };

    /// @brief Hysteria2 帧解析器（wire → 对象）
    class parser
    {
    public:
        /// @brief 增量喂入 wire 字节
        /// @param buffer 输入缓冲
        /// @param ec 输出错误码
        /// @return 本次消耗字节数
        auto put(boost::asio::const_buffer buffer, std::error_code &ec) -> std::size_t
        {
            ec.clear();
            const auto data = std::span<const std::uint8_t>(
                static_cast<const std::uint8_t *>(buffer.data()), buffer.size());
            buf_.insert(buf_.end(), data.begin(), data.end());
            std::size_t consumed = 0;
            const auto err = parse(buf_, msg_, consumed);
            if (err == error::need_more)
            {
                ec = make_error_code(error::need_more);
                return 0;
            }
            if (err != error::none)
            {
                ec = make_error_code(err);
                return 0;
            }
            done_ = true;
            return consumed;
        }

        /// 是否解析完成
        [[nodiscard]] auto is_done() const -> bool
        {
            return done_;
        }

        /// 解析结果（done 后有效）
        [[nodiscard]] auto get() const -> const message &
        {
            return msg_;
        }

        /// 重置解析器
        auto reset() -> void
        {
            buf_.clear();
            msg_ = message{};
            done_ = false;
        }

    private:
        std::vector<std::uint8_t> buf_;
        message msg_{};
        bool done_{false};
    };

} // namespace psmtest::hysteria2
