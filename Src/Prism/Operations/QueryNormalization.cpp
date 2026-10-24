/** @file QueryNormalization.cpp @brief 查询页边界归一化实现。 */
#include <Prism/Operations/Detail/QueryNormalization.hpp>
#include <Prism/Operations/Models.hpp>
#include <Prism/Statistics/EventRing.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>

namespace Prism::Operations::Detail
{
    namespace
    {
        template <typename Value>
        [[nodiscard]] auto PageBoundsForQueryValue(const Value &ValueObject)
            -> std::optional<std::pair<std::uint64_t, std::size_t>>
        {
            using ValueType = std::remove_cvref_t<Value>;
            if constexpr (std::is_same_v<ValueType, ManagementQuery>)
            {
                const auto *Events = std::get_if<EventsRead>(&ValueObject.Value);
                return Events != nullptr ? PageBoundsFor(*Events) : std::nullopt;
            }
            else
            {
                return PageBoundsFor(ValueObject);
            }
        }

        [[nodiscard]] auto PageBounds(const Query &QueryValue)
            -> std::optional<std::pair<std::uint64_t, std::size_t>>
        {
            return std::visit(
                [](const auto &ValueObject) { return PageBoundsForQueryValue(ValueObject); },
                QueryValue.Value);
        }
    }

    [[nodiscard]] auto NormalizeQueryResult(const Query &QueryValue,
                                             QueryResult Result) -> QueryResult
    {
        const auto Bounds = PageBounds(QueryValue);
        if (Bounds)
        {
            std::visit(
                [&Bounds](auto &Payload)
                {
                    using PayloadType = std::remove_cvref_t<decltype(Payload)>;
                    if constexpr (IsPage<PayloadType>::value)
                    {
                        Payload = NormalizePage(std::move(Payload), Bounds->first, Bounds->second);
                    }
                },
                Result.Value);
        }

        const auto *Management = std::get_if<ManagementQuery>(&QueryValue.Value);
        const auto *Events = Management != nullptr
            ? std::get_if<EventsRead>(&Management->Value)
            : nullptr;
        if (Events != nullptr && !Events->IncludeDetails)
        {
            std::visit([](auto &Payload) { ClearEventDetails(Payload); }, Result.Value);
        }
        return Result;
    }
} // namespace Prism::Operations::Detail
