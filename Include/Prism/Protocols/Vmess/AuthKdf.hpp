/**
 * @file AuthKdf.hpp
 * @brief VMess AEAD 链式密钥派生
 * @details 只负责 VMess AEAD KDF；底层摘要、字节视图和 padding 由
 *          AuthCrypto.hpp 提供。
 */

#pragma once

#include <Prism/Protocols/Vmess/AuthCrypto.hpp>
#include <Prism/Protocols/Vmess/Types.hpp>

#include <array>
#include <cstdint>
#include <functional>
#include <span>

namespace Prism::Vmess
{

    namespace Detail
    {

        using KdfFunction = std::function<std::array<std::uint8_t, 32>(std::span<const std::uint8_t>)>;

        /// 一个 VMess KDF 路径阶段；链上的前一阶段由值拥有。
        struct KdfStage final
        {
            KdfFunction Previous;
            std::array<std::uint8_t, 64> Ipad{};
            std::array<std::uint8_t, 64> Opad{};

            [[nodiscard]] auto operator()(std::span<const std::uint8_t> Message) const
                -> std::array<std::uint8_t, 32>;
        };

        [[nodiscard]] auto BaseKdf(std::span<const std::uint8_t> Message) -> std::array<std::uint8_t, 32>;

        auto AppendKdfStage(KdfFunction& Chain, std::span<const std::uint8_t> Path) -> void;

    } // namespace Detail

    /**
     * @brief 执行 VMess AEAD KDF 链式哈希
     * @tparam Path KDF 路径类型
     * @param Key 初始密钥
     * @param Paths KDF 路径列表
     * @return 32 字节派生密钥
     */
    template <typename... Path>
    [[nodiscard]] auto Kdf(std::span<const std::uint8_t> Key, const Path&... Paths)
        -> std::array<std::uint8_t, 32>
    {
        Detail::KdfFunction Chain = Detail::BaseKdf;
        (Detail::AppendKdfStage(Chain, detail::AsBytes(Paths)), ...);
        return Chain(Key);
    }

} // namespace Prism::Vmess
