#pragma once

#include <compare>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace Preview::Identifier
{

    /** @brief 强类型数值标识符。 */
    template <typename Tag, typename ValueType = std::uint64_t>
    class Id final
    {
    public:
        using value_type = ValueType;

        constexpr Id() noexcept = default;

        explicit constexpr Id(const ValueType ValueValue) noexcept : Value_(ValueValue) {}

        [[nodiscard]] constexpr auto Value() const noexcept -> ValueType
        {
            return Value_;
        }

        [[nodiscard]] constexpr explicit operator bool() const noexcept
        {
            return Value_ != ValueType{};
        }

        friend constexpr auto operator==(const Id &, const Id &) noexcept -> bool = default;
        friend constexpr auto operator<=>(const Id &, const Id &) noexcept = default;

    private:
        ValueType Value_{};
    };

    /** @brief 强类型文本标识符，用于 kind/name 等稳定注册键。 */
    template <typename Tag>
    class TextId final
    {
    public:
        TextId() = default;

        explicit TextId(std::string_view Value) : Value_(Value) {}

        explicit TextId(std::string Value) : Value_(std::move(Value)) {}

        [[nodiscard]] static auto From(std::string_view Value) -> TextId
        {
            return TextId(Value);
        }

        [[nodiscard]] auto Value() const noexcept -> std::string_view
        {
            return Value_;
        }

        [[nodiscard]] auto Empty() const noexcept -> bool
        {
            return Value_.empty();
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return !Empty();
        }

        friend auto operator==(const TextId &, const TextId &) noexcept -> bool = default;
        friend auto operator<=>(const TextId &, const TextId &) noexcept = default;

    private:
        std::string Value_;
    };

    struct BuiltinTag;
    struct SnapshotTag;
    struct BuiltinSnapshotTag;
    struct RequestTag;
    struct GenerationTag;
    struct ProcessTag;
    struct WorkerTag;
    struct SessionTag;
    struct StreamTag;
    struct TaskTag;
    struct AccountTag;
    struct KindTag;
    struct NameTag;

    using BuiltinId = Id<BuiltinTag>;
    using SnapshotId = Id<SnapshotTag>;
    using BuiltinSnapshotId = Id<BuiltinSnapshotTag>;
    using RequestId = Id<RequestTag>;
    using GenerationId = Id<GenerationTag>;
    using ProcessId = Id<ProcessTag>;
    using WorkerId = Id<WorkerTag>;
    using SessionId = Id<SessionTag>;
    using StreamId = Id<StreamTag>;
    using TaskId = Id<TaskTag>;
    using AccountId = Id<AccountTag>;
    using KindId = TextId<KindTag>;
    using NameId = TextId<NameTag>;

} // namespace Preview::Identifier

namespace Preview
{

    using Identifier::BuiltinId;
    using Identifier::BuiltinSnapshotId;
    using Identifier::BuiltinSnapshotTag;
    using Identifier::BuiltinTag;
    using Identifier::AccountId;
    using Identifier::AccountTag;
    using Identifier::GenerationId;
    using Identifier::GenerationTag;
    using Identifier::Id;
    using Identifier::KindId;
    using Identifier::NameId;
    using Identifier::ProcessId;
    using Identifier::ProcessTag;
    using Identifier::RequestId;
    using Identifier::SessionId;
    using Identifier::SessionTag;
    using Identifier::SnapshotId;
    using Identifier::SnapshotTag;
    using Identifier::StreamId;
    using Identifier::StreamTag;
    using Identifier::TaskId;
    using Identifier::TaskTag;
    using Identifier::WorkerId;
    using Identifier::WorkerTag;

} // namespace Preview
