/**
 * @file AuthKdf.hpp
 * @brief VMess AEAD 链式密钥派生
 * @details 只负责 VMess AEAD KDF；底层摘要、字节视图和 padding 由
 *          AuthCrypto.hpp 提供。
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <utility>
#include <vector>

#include <Preview/Protocols/Vmess/AuthCrypto.hpp>
#include <Preview/Protocols/Vmess/Types.hpp>

namespace Preview::Vmess
{

    namespace Detail
    {

        using KdfFunction = std::function<std::array<std::uint8_t, 32>(
            std::span<const std::uint8_t>)>;

        /// 一个 VMess KDF 路径阶段；链上的前一阶段由值拥有。
        struct KdfStage final
        {
            KdfFunction Previous;
            std::array<std::uint8_t, 64> Ipad{};
            std::array<std::uint8_t, 64> Opad{};

            [[nodiscard]] auto operator()(std::span<const std::uint8_t> Message) const
                -> std::array<std::uint8_t, 32>
            {
                std::vector<std::uint8_t> InnerIn(64 + Message.size());
                std::copy(Ipad.begin(), Ipad.end(), InnerIn.begin());
                std::copy(Message.begin(), Message.end(), InnerIn.begin() + 64);
                const auto Inner = Previous(InnerIn);

                std::array<std::uint8_t, 64 + 32> OuterIn{};
                std::copy(Opad.begin(), Opad.end(), OuterIn.begin());
                std::copy(Inner.begin(), Inner.end(), OuterIn.begin() + 64);
                return Previous(OuterIn);
            }
        };

        [[nodiscard]] inline auto BaseKdf(std::span<const std::uint8_t> Message)
            -> std::array<std::uint8_t, 32>
        {
            return detail::HmacSha256(detail::AsBytes(KdfInnerMarker), Message);
        }

        inline auto AppendKdfStage(KdfFunction &Chain,
                                   std::span<const std::uint8_t> Path) -> void
        {
            Chain = KdfStage{Chain, detail::XorPad(Path, 0x36), detail::XorPad(Path, 0x5C)};
        }

    } // namespace Detail

    /**
     * @brief 执行 VMess AEAD KDF 链式哈希
     * @tparam Path KDF 路径类型
     * @param Key 初始密钥
     * @param Paths KDF 路径列表
     * @return 32 字节派生密钥
     */
    template <typename... Path>
    [[nodiscard]] auto Kdf(std::span<const std::uint8_t> Key, const Path &...Paths)
        -> std::array<std::uint8_t, 32>
    {
        Detail::KdfFunction Chain = Detail::BaseKdf;
        (Detail::AppendKdfStage(Chain, detail::AsBytes(Paths)), ...);
        return Chain(Key);
    }

} // namespace Preview::Vmess
