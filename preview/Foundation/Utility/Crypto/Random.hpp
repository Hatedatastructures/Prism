/**
 * @file Random.hpp
 * @brief CSPRNG 字节填充工具
 * @details 统一检查 BoringSSL RAND_bytes 的返回值，并提供可注入的源函数
 *          供错误路径测试使用。密码学调用方必须在返回 false 时终止操作。
 */

#pragma once

#include <openssl/rand.h>

#include <cstdint>
#include <limits>
#include <span>
#include <utility>

namespace Preview::Crypto
{

    namespace Detail
    {

        template <typename Source>
        [[nodiscard]] inline auto FillRandomWith(
            std::span<std::uint8_t> Data,
            Source &&SourceFn) -> bool
        {
            if (Data.empty())
            {
                return true;
            }
            if (Data.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            {
                return false;
            }
            return SourceFn(Data.data(), static_cast<int>(Data.size())) == 1;
        }

    } // namespace Detail

    /**
     * @brief 使用默认 CSPRNG 填充字节
     * @param Data 输出缓冲区
     * @return 成功返回 true；随机源失败或长度不可表达返回 false
     */
    [[nodiscard]] inline auto FillRandom(std::span<std::uint8_t> Data) -> bool
    {
        const auto RandBytes = [](std::uint8_t *Bytes, int Size) -> int
        {
            return RAND_bytes(Bytes, Size);
        };
        return Detail::FillRandomWith(Data, RandBytes);
    }

    /**
     * @brief 使用注入源填充字节
     * @param Data 输出缓冲区
     * @param SourceFn 兼容 RAND_bytes 签名的源函数
     * @return 源函数返回 1 且长度合法时返回 true
     */
    template <typename Source>
    [[nodiscard]] inline auto FillRandom(std::span<std::uint8_t> Data, Source &&SourceFn) -> bool
    {
        return Detail::FillRandomWith(Data, std::forward<Source>(SourceFn));
    }

} // namespace Preview::Crypto
