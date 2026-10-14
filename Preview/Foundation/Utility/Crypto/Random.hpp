/**
 * @file Random.hpp
 * @brief CSPRNG 字节填充与显式失败结果。
 */
#pragma once

#include <Preview/Foundation/Utility/Crypto/Operation.hpp>
#include <openssl/rand.h>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <utility>

namespace Preview::Crypto
{
    namespace Detail
    {
        /** @brief 同步借用输出和随机源；原生失败擦除输出并保留错误类别。 */
        template <typename Source>
        [[nodiscard]] inline auto FillRandomWith(const std::span<std::uint8_t> Data,
                                                Source &&SourceFn)
            -> std::expected<void, Fault::Failure>
        {
            if (Data.empty())
            {
                return {};
            }
            if (Data.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return std::unexpected(Fault::Failure{Fault::Code::InvalidArgument, {}});
            }
            ERR_clear_error();
            if (SourceFn(Data.data(), static_cast<int>(Data.size())) != 1)
            {
                const auto Failure = NativeFailure(Fault::Code::CryptoError);
                OPENSSL_cleanse(Data.data(), Data.size());
                return std::unexpected(Failure);
            }
            return {};
        }
    }

    /**
     * @brief 使用默认 CSPRNG 填充调用者拥有的缓冲区。
     * @details 借用持续至返回；无效长度不写输出，随机失败擦除输出且调用者必须终止操作。
     *          不抛出异常，无取消、半关闭、最终关闭或 executor 行为。
     * @return 成功为空 expected，失败包含 Failure，不以输出字节判断成败。
     */
    [[nodiscard]] inline auto FillRandom(const std::span<std::uint8_t> Data)
        -> std::expected<void, Fault::Failure>
    {
        const auto RandBytes = [](std::uint8_t *Bytes, const int Size) -> int
        {
            return RAND_bytes(Bytes, Size);
        };
        return Detail::FillRandomWith(Data, RandBytes);
    }

    /**
     * @brief 使用注入随机源填充输出，输出与生命周期契约同默认版本。
     * @param Data 调用者拥有的可写缓冲区。
     * @param SourceFn 同步调用且不抛异常的 RAND_bytes 签名随机源，返回 1 才表示成功。
     * @return 随机失败返回 CryptoError，长度非法返回 InvalidArgument。
     */
    template <typename Source>
    [[nodiscard]] inline auto FillRandom(const std::span<std::uint8_t> Data, Source &&SourceFn)
        -> std::expected<void, Fault::Failure>
    {
        return Detail::FillRandomWith(Data, std::forward<Source>(SourceFn));
    }
}
