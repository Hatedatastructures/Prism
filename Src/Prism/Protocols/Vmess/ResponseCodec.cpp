/**
 * @file ResponseCodec.cpp
 * @brief VMess 响应头编解码实现。
 */

#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/AuthHeader.hpp>
#include <Prism/Protocols/Vmess/AuthId.hpp>
#include <Prism/Protocols/Vmess/AuthKdf.hpp>
#include <Prism/Protocols/Vmess/ResponseCodec.hpp>

#include <cstring>

namespace Prism::Vmess
{
    [[nodiscard]] auto SealResponseHeader(std::span<const std::uint8_t, 16> RespKey,
        const RespHeaderInput& Input) -> std::vector<std::uint8_t>
    {
        return detail::AesGcmSeal(detail::SealInput{RespKey, Input.iv, Input.v, {}});
    }

    [[nodiscard]] auto OpenResponseHeader(std::span<const std::uint8_t, 16> RespKey,
        const RespHeaderParseInput& Input, ResponseHeader& Output) -> Error
    {
        constexpr auto AeadTagLength = std::size_t{16};
        if (Input.Data.size() < AeadTagLength)
        {
            return Error::NeedMore;
        }
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

    [[nodiscard]] auto MakeResponse(const Message& MessageValue, std::string& Response) -> bool
    {
        Response.clear();
        const auto RespBodyKey = detail::Sha256(MessageValue.RequestKey);
        const auto RespBodyIv = detail::Sha256(MessageValue.RequestNonce);
        std::array<std::uint8_t, 16> ResponseKey{};
        std::memcpy(ResponseKey.data(), RespBodyKey.data(), 16);
        std::array<std::uint8_t, 16> ResponseIv{};
        std::memcpy(ResponseIv.data(), RespBodyIv.data(), 16);

        const std::array<std::uint8_t, 4> ResponsePlain{MessageValue.RespHeader, MessageValue.Option, 0, 0};
        const auto ResponseKeyPath = Kdf(ResponseKey, KdfRespKey);
        const auto ResponseIvPath = Kdf(ResponseIv, KdfRespIv);
        std::array<std::uint8_t, 16> ResponseKeyBytes{};
        std::memcpy(ResponseKeyBytes.data(), ResponseKeyPath.data(), 16);
        std::array<std::uint8_t, 12> ResponseIvBytes{};
        std::memcpy(ResponseIvBytes.data(), ResponseIvPath.data(), 12);
        const auto ResponseEncrypted =
            SealResponseHeader(ResponseKeyBytes, RespHeaderInput{ResponseIvBytes, ResponsePlain});
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
        const auto LengthEncrypted = detail::AesGcmSeal(
            detail::SealInput{ResponseLengthKeyBytes, ResponseLengthIvBytes, ResponseLengthPlain, {}});
        if (LengthEncrypted.size() != 18)
        {
            return true;
        }

        Response.reserve(LengthEncrypted.size() + ResponseEncrypted.size());
        Response.insert(Response.end(), LengthEncrypted.begin(), LengthEncrypted.end());
        Response.insert(Response.end(), ResponseEncrypted.begin(), ResponseEncrypted.end());
        return false;
    }

} // namespace Prism::Vmess
