/**
 * @file QueryNormalization.hpp
 * @brief Prism 管理查询页的边界归一化与敏感事件裁剪。
 */

#pragma once

#include <Prism/Operations/Models.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>

namespace Prism::Operations
{
    namespace Detail
    {

        template <typename Value>
        struct IsPage : std::false_type
        {
        };

        template <typename Value>
        struct IsPage<Page<Value>> : std::true_type
        {
        };

        template<>
        struct IsPage<Prism::Statistics::EventPage> : std::true_type {};

        template <typename Value>
        [[nodiscard]] auto CursorOf(const Value &ValueObject) noexcept -> std::uint64_t
        {
            if constexpr (std::is_same_v<std::remove_cvref_t<Value>, EventSnapshot>)
            {
                return ValueObject.Sequence;
            }
            else
            {
                return ValueObject.Id.Value();
            }
        }

        template <typename Value>
        [[nodiscard]] auto NormalizePage(Value ValuePage,
                                          const std::uint64_t Cursor,
                                          const std::size_t Limit) -> Value
        {
            Value Result;
            if constexpr (std::is_same_v<Value, Prism::Statistics::EventPage>)
            {
                Result.EarliestCursor = ValuePage.EarliestCursor;
                Result.Lost = ValuePage.Lost;
                Result.LostRanges = std::move(ValuePage.LostRanges);
            }
            Result.HasMore = ValuePage.HasMore;
            for (auto &Item : ValuePage.Items)
            {
                if (CursorOf(Item) <= Cursor)
                {
                    continue;
                }
                if (Limit == 0)
                {
                    Result.HasMore = true;
                    break;
                }
                if (Result.Items.size() >= Limit)
                {
                    Result.HasMore = true;
                    break;
                }
                Result.Items.push_back(std::move(Item));
            }

            if (Result.Items.empty())
            {
                Result.NextCursor = Cursor;
            }
            else
            {
                Result.NextCursor = CursorOf(Result.Items.back());
            }
            return Result;
        }

        template <typename Value>
        [[nodiscard]] auto PageBoundsFor(const Value &ValueObject)
            -> std::optional<std::pair<std::uint64_t, std::size_t>>
        {
            if constexpr (requires { ValueObject.Page.Cursor; ValueObject.Page.Limit; })
                return std::pair{ValueObject.Page.Cursor, ValueObject.Page.BoundedLimit()};
            else
                return std::nullopt;
        }

        template <typename Value>
        auto ClearEventDetails(Value &Payload) -> void
        {
            if constexpr (std::is_same_v<std::remove_cvref_t<Value>, Prism::Statistics::EventPage>)
            {
                for (auto &EventValue : Payload.Items) EventValue.Detail.clear();
            }
        }

        [[nodiscard]] inline auto PageBounds(const Query &QueryValue)
            -> std::optional<std::pair<std::uint64_t, std::size_t>>
        {
            return std::visit(
                [](const auto &ValueObject) { return PageBoundsFor(ValueObject); },
                QueryValue.Value);
        }

        [[nodiscard]] inline auto NormalizeQueryResult(const Query &QueryValue,
                                                        QueryResult Result) -> QueryResult
        {
            const auto Bounds = PageBounds(QueryValue);
            if (!Bounds)
            {
                return Result;
            }

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

            const auto *EventQueryValue = std::get_if<EventQuery>(&QueryValue.Value);
            if (EventQueryValue != nullptr && !EventQueryValue->IncludeDetails)
            {
                std::visit(
                    [](auto &Payload) { ClearEventDetails(Payload); },
                    Result.Value);
            }
            return Result;
        }

    } // namespace Detail

} // namespace Prism::Operations
