/**
 * @file PrefixCache.hpp
 * @brief Worker/Session 固定前缀缓存。
 */
#pragma once

#include <Prism/Foundation/Identifier/Id.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace Prism::Diagnose
{

    /**
     * @brief Worker 和 Session 固定身份的人类日志前缀缓存。
     * @details 前缀按 Worker、Session 顺序格式化为紧凑文本，并保存在对象内的固定容量缓冲区中。
     *          WithWorker() 或 WithSession() 派生身份时重建；读取日志前缀时只返回缓冲区视图，不分配也不重新格式化。
     */
    class PrefixCache final
    {
    public:
        /**
         * @brief 获取缓存的人类可读前缀。
         * @return 指向对象内部缓冲区的视图；没有身份时返回空视图。
         * @details 视图不拥有存储，必须在此 PrefixCache 对象存活且未被赋值覆盖期间使用。
         */
        [[nodiscard]] auto View() const noexcept -> std::string_view
        {
            return {Buffer_.data(), Size_};
        }

        /**
         * @brief 获取缓存的 Worker 身份。
         * @return 已设置时返回 WorkerId，否则返回 std::nullopt。
         */
        [[nodiscard]] auto Worker() const noexcept -> std::optional<Prism::WorkerId>
        {
            return Worker_;
        }

        /**
         * @brief 获取缓存的 Session 身份。
         * @return 已设置时返回 SessionId，否则返回 std::nullopt。
         */
        [[nodiscard]] auto Session() const noexcept -> std::optional<Prism::SessionId>
        {
            return Session_;
        }

        /**
         * @brief 派生带指定 Worker 身份的前缀缓存。
         * @param Value 要设置的 Worker 身份。
         * @return 保留原 Session 身份、更新 Worker 并重建前缀的新缓存。
         */
        [[nodiscard]] auto WithWorker(const Prism::WorkerId Value) const noexcept -> PrefixCache
        {
            auto Result = *this;
            Result.Worker_ = Value;
            Result.Rebuild();
            return Result;
        }

        /**
         * @brief 派生带指定 Session 身份的前缀缓存。
         * @param Value 要设置的 Session 身份。
         * @return 保留原 Worker 身份、更新 Session 并重建前缀的新缓存。
         */
        [[nodiscard]] auto WithSession(const Prism::SessionId Value) const noexcept -> PrefixCache
        {
            auto Result = *this;
            Result.Session_ = Value;
            Result.Rebuild();
            return Result;
        }

    private:
        /**
         * @brief 将一个身份标记和无符号 ID 追加到固定缓冲区。
         * @param Kind 身份类型标记；Worker 使用 W，Session 使用 S。
         * @param Value 身份 ID，按十进制格式写入。
         * @details 调用方保证固定缓冲区有足够空间；此操作不分配动态内存。
         */
        auto Append(const char Kind, const std::uint64_t Value) noexcept -> void;

        /**
         * @brief 根据已设置的身份重建完整前缀。
         * @details 先清空缓存，再依次追加 Worker 和 Session；只在身份派生时调用，不在每条日志读取时调用。
         */
        auto Rebuild() noexcept -> void;

        std::array<char, 48> Buffer_{}; ///< 固定容量的 [W<id>][S<id>] 文本缓冲区。
        std::size_t Size_{0U}; ///< Buffer_ 中有效前缀的字节数。
        std::optional<Prism::WorkerId> Worker_; ///< 可选的 Worker 身份。
        std::optional<Prism::SessionId> Session_; ///< 可选的 Session 身份。
    };

} // namespace Prism::Diagnose
