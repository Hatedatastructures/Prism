/**
 * @file RequestState.hpp
 * @brief Shadowsocks 2022 请求增量 Serializer/Parser 状态机。
 * @details Serializer 负责生成完整首包，Parser 负责跨多次 Put 调用
 *          解密并解析固定头、变长头和初始载荷。无状态 wire helper
 *          位于 RequestWire.hpp。
 */

#pragma once

#include <boost/asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <random>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include <Prism/Foundation/Error.hpp>
#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Protocols/Shadowsocks2022/ChunkCodec.hpp>
#include <Prism/Protocols/Shadowsocks2022/KeyDerivation.hpp>
#include <Prism/Protocols/Shadowsocks2022/RequestWire.hpp>
#include <Prism/Protocols/Shadowsocks2022/Types.hpp>

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
        using RandomSource = std::function<int(std::uint8_t *, int)>;
        /**
         * @brief 构造
         * @param Psk 预共享密钥（16 字节）
         */
        explicit Serializer(
            const std::array<std::uint8_t, 16> &Psk,
            RandomSource Source = {})
            : Psk_(Psk), Source_(std::move(Source))
        {
        }

        /**
         * @brief 重置并绑定消息
         * @param MessageValue 消息
         * @param TimeSec UTC 秒
         */
        auto Reset(const Message &MessageValue, std::uint64_t TimeSec) -> void
        {
            Wire_.clear();
            Offset_ = 0;
            Ready_ = false;
            Failed_ = false;
            std::array<std::uint8_t, 16> Salt{};
            bool Filled;
            if (Source_)
            {
                Filled = Prism::Crypto::FillRandom(std::span<std::uint8_t>(Salt), Source_).has_value();
            }
            else
            {
                Filled = Prism::Crypto::FillRandom(std::span<std::uint8_t>(Salt)).has_value();
            }
            if (!Filled)
            {
                Failed_ = true;
                return;
            }
            const auto SessionKeyValue = SessionKey(Psk_, Salt, 16);

            std::random_device RandomDevice;
            const auto PaddingLength = static_cast<std::uint16_t>(1 + RandomDevice() % 16);
            std::vector<std::uint8_t> VariableHeader;
            const auto AddressBytes = EncodeAddress(MessageValue.dst);
            if (AddressBytes.empty())
            {
                Failed_ = true;
                return;
            }
            VariableHeader.insert(VariableHeader.end(), AddressBytes.begin(), AddressBytes.end());
            VariableHeader.push_back(static_cast<std::uint8_t>((PaddingLength >> 8) & 0xFF));
            VariableHeader.push_back(static_cast<std::uint8_t>(PaddingLength & 0xFF));
            for (std::uint16_t I = 0; I < PaddingLength; ++I)
            {
                VariableHeader.push_back(static_cast<std::uint8_t>(RandomDevice() & 0xFF));
            }
            VariableHeader.insert(
                VariableHeader.end(),
                MessageValue.InitialPayload.begin(),
                MessageValue.InitialPayload.end());
            if (VariableHeader.size() > (std::numeric_limits<std::uint16_t>::max)())
            {
                Failed_ = true;
                return;
            }

            const auto Fixed = ParseFixedHeader(
                HeaderTypeClient,
                TimeSec,
                static_cast<std::uint16_t>(VariableHeader.size()));
            ChunkCodec Codec(SessionKeyValue);
            const auto FixedEncrypted = Codec.SealRaw(Fixed);
            const auto VariableEncrypted = Codec.SealRaw(VariableHeader);
            if (FixedEncrypted.empty() || VariableEncrypted.empty())
            {
                Failed_ = true;
                return;
            }

            Wire_.clear();
            Wire_.reserve(Salt.size() + FixedEncrypted.size() + VariableEncrypted.size());
            Wire_.insert(Wire_.end(), Salt.begin(), Salt.end());
            Wire_.insert(Wire_.end(), FixedEncrypted.begin(), FixedEncrypted.end());
            Wire_.insert(Wire_.end(), VariableEncrypted.begin(), VariableEncrypted.end());
            Ready_ = !Wire_.empty();
        }

        /**
         * @brief 增量输出
         * @param Buffer 输出缓冲区
         * @param ErrorCode 错误码
         * @return 实际写入字节数
         */
        auto Get(
            boost::asio::mutable_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            if (!Ready_)
            {
                ErrorCode = make_error_code(Error::IoError);
                return 0;
            }
            const auto N = std::min(Buffer.size(), Wire_.size() - Offset_);
            std::memcpy(Buffer.data(), Wire_.data() + Offset_, N);
            Offset_ += N;
            return N;
        }

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
        explicit Parser(const std::array<std::uint8_t, 16> &Psk) : Psk_(Psk)
        {
        }

        /**
         * @brief 增量喂入
         * @param Buffer 输入缓冲区
         * @param ErrorCode 错误码
         * @return 已累积缓冲字节数
         */
        auto Put(
            boost::asio::const_buffer Buffer,
            std::error_code &ErrorCode) -> std::size_t
        {
            ErrorCode.clear();
            if (Done_)
            {
                return 0;
            }
            const auto Data = std::span<const std::uint8_t>(static_cast<const std::uint8_t *>(Buffer.data()),
                                                            Buffer.size());
            Buf_.insert(Buf_.end(), Data.begin(), Data.end());
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen)
            {
                ErrorCode = make_error_code(Error::NeedMore);
                return 0;
            }

            const auto Salt = std::span<const std::uint8_t>(Buf_).first(16);
            const auto SessionKeyValue = SessionKey(Psk_, Salt, 16);
            ChunkCodec Codec(SessionKeyValue);
            auto FixedPlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                   16, FixedHdrPlain + AeadTagLen));
            if (FixedPlain.size() != FixedHdrPlain || FixedPlain[0] != HeaderTypeClient)
            {
                ErrorCode = make_error_code(Error::BadAuth);
                return 0;
            }
            FixedHeader FixedHeaderValue;
            if (ParseFixedHeader(FixedPlain, FixedHeaderValue) != Error::None)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return 0;
            }
            TimeSec_ = FixedHeaderValue.TimeSec;
            const auto VariableLength = static_cast<std::size_t>(FixedHeaderValue.VarLen);
            if (Buf_.size() < 16 + FixedHdrPlain + AeadTagLen + VariableLength + AeadTagLen)
            {
                ErrorCode = make_error_code(Error::NeedMore);
                return 0;
            }
            auto VariablePlain = Codec.OpenRaw(std::span<const std::uint8_t>(Buf_).subspan(
                                                       16 + FixedHdrPlain + AeadTagLen,
                                                       VariableLength + AeadTagLen));
            if (VariablePlain.empty())
            {
                ErrorCode = make_error_code(Error::BadAuth);
                return 0;
            }

            std::size_t Offset = 0;
            const auto AddressError = ParseAddress(
                std::span<const std::uint8_t>(VariablePlain).subspan(Offset),
                Msg_.dst,
                Offset);
            if (AddressError != Error::None)
            {
                ErrorCode = make_error_code(AddressError);
                return 0;
            }
            if (VariablePlain.size() - Offset < 2)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return 0;
            }
            const auto PaddingLength =
                static_cast<std::size_t>(VariablePlain[Offset]) << 8 | VariablePlain[Offset + 1];
            Offset += 2;
            if (VariablePlain.size() - Offset < PaddingLength)
            {
                ErrorCode = make_error_code(Error::BadMessage);
                return 0;
            }
            Offset += PaddingLength;
            Msg_.InitialPayload.assign(
                reinterpret_cast<const char *>(VariablePlain.data() + Offset),
                VariablePlain.size() - Offset);
            Done_ = true;
            return Buf_.size();
        }

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
        [[nodiscard]] auto Get() const -> const Message &
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
        [[nodiscard]] auto IsTimestampFresh(std::uint64_t TimeWindow) const noexcept -> bool
        {
            const auto Now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            std::uint64_t Difference;
            if (Now >= TimeSec_)
            {
                Difference = Now - TimeSec_;
            }
            else
            {
                Difference = TimeSec_ - Now;
            }
            return Difference <= TimeWindow;
        }

        /**
         * @brief 重置解析状态
         */
        auto Reset() -> void
        {
            Buf_.clear();
            Msg_ = Message{};
            TimeSec_ = 0;
            Done_ = false;
        }

    private:
        std::array<std::uint8_t, 16> Psk_;
        std::vector<std::uint8_t> Buf_;
        Message Msg_{};
        std::uint64_t TimeSec_{0};
        bool Done_{false};
    };

} // namespace Prism::Shadowsocks2022
