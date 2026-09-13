/**
 * @file ResponseCodec.hpp
 * @brief VMess 响应头编解码
 * @details 响应头使用请求消息中的 key/nonce 派生密钥，并以 AuthID
 *          作为 AEAD 附加认证数据。请求消息和认证原语分别来自
 *          RequestCodec.hpp 与 Auth.hpp。
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include <preview/Protocols/Vmess/Auth.hpp>
#include <preview/Protocols/Vmess/RequestCodec.hpp>
#include <preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    /**
     * @brief 响应头密封输入（IV + V + AuthID）
     */
    struct RespHeaderInput
    {
        std::span<const std::uint8_t, 12> iv;
        std::span<const std::uint8_t, 4> v;
        std::span<const std::uint8_t, 16> AuthId;
    };

    /**
     * @brief 响应头解析输入（IV + 密文 + AuthID）
     */
    struct RespHeaderParseInput
    {
        std::span<const std::uint8_t, 12> iv;
        std::span<const std::uint8_t> Data;
        std::span<const std::uint8_t, 16> AuthId;
    };

    /**
     * @brief 密封响应头
     * @param RespKey 16 字节响应密钥
     * @param Input 输入（iv + v + AuthId）
     * @return 响应头密文（4 + 16 tag）
     */
    [[nodiscard]] inline auto SealResponseHeader(
        std::span<const std::uint8_t, 16> RespKey,
        const RespHeaderInput &Input) -> std::vector<std::uint8_t>
    {
        // 标准 VMess AEAD 响应头不使用 AuthID 作为 AAD；字段保留在
        // 输入结构中仅为兼容旧调用方，避免把认证头语义带入响应方向。
        (void)Input.AuthId;
        return detail::AesGcmSeal(detail::SealInput{RespKey, Input.iv, Input.v, {}});
    }

    /**
     * @brief 打开响应头
     * @param RespKey 16 字节响应密钥
     * @param Input 输入（iv + Data + AuthId）
     * @param Output 输出响应头
     * @return 错误码
     */
    [[nodiscard]] inline auto OpenResponseHeader(
        std::span<const std::uint8_t, 16> RespKey,
        const RespHeaderParseInput &Input,
        ResponseHeader &Output)
        -> Error
    {
        constexpr auto AeadTagLength = std::size_t{16};
        if (Input.Data.size() < AeadTagLength)
        {
            return Error::NeedMore;
        }
        (void)Input.AuthId;
        const auto Plain = detail::AesGcmOpen(detail::OpenInput{RespKey, Input.iv, Input.Data, {}});
        if (Plain.empty())
        {
            return Error::BadAuth;
        }
        if (Plain.size() != 4)
        {
            return Error::BadLength;
        }
        Output.Version = Plain[0];
        std::memcpy(Output.v.data(), Plain.data(), 4);
        return Error::None;
    }

    /**
     * @brief 构造 VMess AEAD 响应头
     * @param MessageValue 请求消息（RequestKey / RequestNonce / RespHeader）
     * @param Response 输出响应字节
     * @return false = 成功（保留历史 API 语义）
     */
    [[nodiscard]] inline auto MakeResponse(
        const Message &MessageValue,
        std::string &Response) -> bool
    {
        Response.clear();
        const auto RespBodyKey = detail::Sha256(MessageValue.RequestKey);
        const auto RespBodyIv = detail::Sha256(MessageValue.RequestNonce);
        std::array<std::uint8_t, 16> ResponseKey{};
        std::memcpy(ResponseKey.data(), RespBodyKey.data(), 16);
        std::array<std::uint8_t, 16> ResponseIv{};
        std::memcpy(ResponseIv.data(), RespBodyIv.data(), 16);

        const auto AuthId = std::span<const std::uint8_t, AuthHeaderLen>(MessageValue.AuthId);

        const std::array<std::uint8_t, 4> ResponsePlain{MessageValue.RespHeader, MessageValue.Option, 0, 0};
        const auto ResponseKeyPath = Kdf(ResponseKey, KdfRespKey);
        const auto ResponseIvPath = Kdf(ResponseIv, KdfRespIv);
        std::array<std::uint8_t, 16> ResponseKeyBytes{};
        std::memcpy(ResponseKeyBytes.data(), ResponseKeyPath.data(), 16);
        std::array<std::uint8_t, 12> ResponseIvBytes{};
        std::memcpy(ResponseIvBytes.data(), ResponseIvPath.data(), 12);
        const auto ResponseEncrypted = SealResponseHeader(
            ResponseKeyBytes,
            RespHeaderInput{ResponseIvBytes, ResponsePlain, AuthId});
        if (ResponseEncrypted.size() != 20)
        {
            return true;
        }

        const auto ResponseLengthKey = Kdf(ResponseKey, KdfRespLenKey);
        const auto ResponseLengthIv = Kdf(ResponseIv, KdfRespLenIv);
        std::array<std::uint8_t, 16> ResponseLengthKeyBytes{};
        std::memcpy(ResponseLengthKeyBytes.data(), ResponseLengthKey.data(), 16);
        std::array<std::uint8_t, 12> ResponseLengthIvBytes{};
        std::memcpy(ResponseLengthIvBytes.data(), ResponseLengthIv.data(), 12);
        const std::array<std::uint8_t, 2> ResponseLengthPlain{0, 4};
        const auto LengthEncrypted = detail::AesGcmSeal(detail::SealInput{
            ResponseLengthKeyBytes,
            ResponseLengthIvBytes,
            ResponseLengthPlain,
            {}});
        if (LengthEncrypted.size() != 18)
        {
            return true;
        }

        Response.reserve(LengthEncrypted.size() + ResponseEncrypted.size());
        Response.insert(Response.end(), LengthEncrypted.begin(), LengthEncrypted.end());
        Response.insert(Response.end(), ResponseEncrypted.begin(), ResponseEncrypted.end());
        return false;
    }

} // namespace Preview::Vmess
