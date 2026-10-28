/** @file Storage.hpp
 * @brief 进程拥有的有界不可变上下文槽与固定文本存储。
 */
#pragma once
#include <Prism/Foundation/Utility/Diagnose/FieldCatalog.hpp>
#include <Prism/Foundation/Utility/Diagnose/PrefixCache.hpp>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <utility>

namespace Prism::Diagnose::Detail
{
    /** @brief 每个字段使用目录定义的真实容量，不给全部文本都分配最大字段容量。 */
    inline constexpr auto ContextTextOffsets = []
    {
        std::array<std::size_t, FieldCatalog::Count + 1U> Result{};
        for (const auto& Descriptor : FieldCatalog::Descriptors())
        {
            const auto Index = static_cast<std::size_t>(Descriptor.Id);
            Result[Index + 1U] = Result[Index] + Descriptor.MaxLength;
        }
        return Result;
    }();
    /** @brief 固定字段载荷；文本由绑定所在上下文或快照拥有。 */
    union FieldPayload final
    {
        std::uint64_t Unsigned;
        bool Boolean;
        std::string_view Text;
        constexpr FieldPayload() noexcept : Unsigned(0U) {}
    };
    /** @brief 字段绑定；借用文本须在提交或长期派生时复制。 */
    struct FieldBinding final
    {
        FieldId Id{};
        FieldValueKind Kind{FieldValueKind::Unsigned};
        bool BorrowedText{false};
        bool Truncated{false};
        FieldPayload Payload{};
    };
    /** @brief 固定文本复制，按既有字段预算标记 UTF-8 截断。 */
    [[nodiscard]] auto StoreFieldText(const std::string_view Input,
        const std::span<char> Output, const bool Sensitive) noexcept -> std::pair<std::size_t, bool>;
    /** @brief 单个长期上下文只拥有每个字段的当前文本。 */
    struct ContextStorage final
    {
        static constexpr std::size_t TextBytes = 256U;
        PrefixCache Prefix{};
        std::array<FieldBinding, FieldCatalog::Count> Overflow{};
        std::array<char, ContextTextOffsets.back()> Text{};
        std::uint8_t Count{0U};
        /** @brief 固定存储复制后重新绑定自身文本地址。 */
        auto Rebind() noexcept -> void;
        /** @brief 替换或新增一个目录字段，文本直接归当前槽拥有。 */
        auto Set(FieldBinding Binding) noexcept -> void;
    };
    /** @brief process 固定上下文池；原子位图取得和归还均有界。 */
    class ContextPool final
    {
    public:
        static constexpr std::size_t Capacity = 4096U;
        static constexpr std::size_t WordCount = Capacity / 64U;
        struct Slot final
        {
            std::atomic<std::uint32_t> References{0U};
            ContextStorage Value{};
        };
        /** @brief 取得槽；容量耗尽或竞争返回空值，不等待。 */
        [[nodiscard]] auto TryAcquire() noexcept -> Slot*;
        /** @brief 最后一个引用退出时无分配归还实际槽。 */
        auto Release(Slot* Value) noexcept -> void;
        /** @brief 静态存储期唯一 owner，无惰性堆分配。 */
        [[nodiscard]] static auto Get() noexcept -> ContextPool&;
    private:
        std::array<Slot, Capacity> Slots_{};
        std::array<std::atomic<std::uint64_t>, WordCount> Used_{};
        std::atomic<std::size_t> Hint_{0U};
    };
    extern constinit ContextPool ProcessContextPool; ///< 静态初始化，不在首条请求时取得 guard 或分配。
    inline auto ContextPool::Get() noexcept -> ContextPool& { return ProcessContextPool; }
    /** @brief copy/move 只调整槽引用，归还不分配且无 executor 依赖。 */
    class ContextOwner final
    {
    public:
        ContextOwner() = default;
        explicit ContextOwner(ContextPool::Slot* Slot) noexcept;
        ContextOwner(const ContextOwner& Other) noexcept;
        ContextOwner(ContextOwner&& Other) noexcept;
        auto operator=(ContextOwner Other) noexcept -> ContextOwner&;
        ~ContextOwner();
        explicit operator bool() const noexcept { return Slot_ != nullptr; }
        auto operator->() const noexcept -> ContextStorage* { return &Slot_->Value; }
        [[nodiscard]] auto Get() const noexcept -> ContextStorage& { return Slot_->Value; }
        /** @brief 取得独立可修改副本；失败为空 owner。 */
        [[nodiscard]] auto Clone() const noexcept -> ContextOwner;
    private:
        ContextPool::Slot* Slot_{nullptr};
    };
}
