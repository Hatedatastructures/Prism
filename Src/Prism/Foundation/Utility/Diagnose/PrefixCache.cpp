/**
 * @file PrefixCache.cpp
 * @brief Worker/Session 前缀的固定缓冲构建实现。
 */
#include <Prism/Foundation/Utility/Diagnose/PrefixCache.hpp>

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace Prism::Diagnose
{
    auto PrefixCache::Append(const char Kind, const std::uint64_t Value) noexcept -> void
    {
        Buffer_[Size_++] = '[';
        Buffer_[Size_++] = Kind;
        const auto Result = std::to_chars(Buffer_.data() + Size_, Buffer_.data() + Buffer_.size(), Value);
        if (Result.ec == std::errc{})
        {
            Size_ = static_cast<std::size_t>(Result.ptr - Buffer_.data());
        }
        Buffer_[Size_++] = ']';
    }

    auto PrefixCache::Rebuild() noexcept -> void
    {
        Buffer_.fill('\0');
        Size_ = 0U;
        if (Worker_)
        {
            Append('W', Worker_->Value());
        }
        if (Session_)
        {
            Append('S', Session_->Value());
        }
    }
}
