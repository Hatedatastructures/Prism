/** @file DeferredMessage.hpp
 * @brief 编译期检查的格式描述与无分配拥有型参数快照。
 */
#pragma once
#include <Prism/Foundation/Utility/Crypto/SecretScope.hpp>
#include <Prism/Foundation/Utility/Text/View.hpp>
#include <Prism/Foundation/Utility/Text/Truncate.hpp>
#include <Prism/Foundation/Utility/Diagnose/Detail/FormatValidation.hpp>

#include <array>
#include <concepts>
#include <cstddef>
#include <cstring>
#include <format>
#include <iterator>
#include <locale>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace Prism::Diagnose::Detail
{
    /** @brief 后台渲染结果；截断是输出事实，不能冒充完整消息。 */
    struct RenderedMessage final
    {
        std::string Text{}; ///< 后台拥有的最多 64 KiB 消息。
        bool Truncated{false}; ///< 格式化结果超过输出预算。
    };

    /** @brief 有界输出迭代器的共同状态，只在后台线程上使用。 */
    struct FormatOutput final
    {
        std::span<char> Storage;
        std::size_t Written{0U};
        bool Truncated{false};
    };

    /** @brief 支持标准格式化全部语法，同时将实际保留量限制在固定输出区。 */
    class FormatIterator final
    {
    public:
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::output_iterator_tag;

        explicit FormatIterator(FormatOutput& Output) noexcept : Output_(&Output) {}
        auto operator*() noexcept -> FormatIterator& { return *this; }
        auto operator++() noexcept -> FormatIterator& { return *this; }
        auto operator++(int) noexcept -> FormatIterator { return *this; }
        auto operator=(const char Value) noexcept -> FormatIterator&
        {
            if (Output_->Written < Output_->Storage.size())
            {
                Output_->Storage[Output_->Written++] = Value;
            }
            else
            {
                Output_->Truncated = true;
            }
            return *this;
        }
    private:
        FormatOutput* Output_;
    };

    /**
     * @brief 冷分配队列槽内的消息 owner。
     * @details 提交时复制格式文本与参数文本，数值按原类型复制；不保存借用引用。
     *          超出快照预算返回 false，不截短语义参数；后台渲染才使用标准格式化器。
     *          不管理取消或 executor；实际 owner 是所属队列槽，消费完成后 Reset。
     */
    class DeferredMessage final
    {
    public:
        static constexpr std::size_t SnapshotBytes = 8192U;
        static constexpr std::size_t ArgumentBytes = 512U;
        static constexpr std::size_t MaximumArguments = 16U;
        static constexpr std::size_t RenderBytes = 64U * 1024U;
        DeferredMessage() = default;
        DeferredMessage(const DeferredMessage&) = delete;
        auto operator=(const DeferredMessage&) -> DeferredMessage& = delete;

        /** @brief 清除槽内描述；参数仅含平凡析构值，不触发分配或回调。 */
        auto Reset() noexcept -> void
        {
            const Crypto::SecretScope TextCleanup(std::span(
                reinterpret_cast<std::uint8_t*>(Storage_.data()), Used_));
            const Crypto::SecretScope ArgumentCleanup(std::span(
                reinterpret_cast<std::uint8_t*>(Arguments_.data()), Arguments_.size()));
            Used_ = 0U;
            Format_ = {};
            Render_ = nullptr;
        }

        /** @brief 无分配复制已生成的消息；过大消息明确拒绝。 */
        [[nodiscard]] auto CaptureText(const std::string_view Text, const FormattingLimits& Limits) noexcept
            -> Prism::Fault::Failure
        {
            Reset();
            if (!Limits.Valid()) { return {Prism::Fault::Code::InvalidArgument}; }
            if (Text.size() > Limits.WorkBytes || !CopyText(Text, Format_))
            {
                return {Prism::Fault::Code::OversizedMsg};
            }
            Render_ = &RenderText;
            return {};
        }

        /** @brief 将编译期已检查的格式与实参复制入当前稳定槽。 */
        template <typename... Args>
        [[nodiscard]] auto Capture(const std::format_string<Args...> Format,
            const std::tuple<Args&...>& Inputs, const FormattingLimits& Limits) noexcept -> Prism::Fault::Failure
        {
            using Values = std::tuple<SnapshotType<Args>...>;
            static_assert(sizeof...(Args) <= MaximumArguments);
            static_assert(sizeof(Values) <= ArgumentBytes);
            static_assert(alignof(Values) <= alignof(std::max_align_t));
            static_assert(std::is_trivially_destructible_v<Values>);
            static_assert(std::is_nothrow_copy_constructible_v<Values>);
            Reset();
            if (!Limits.Valid()) { return {Prism::Fault::Code::InvalidArgument}; }
            if (!CopyText(Format.get(), Format_))
            {
                return {Prism::Fault::Code::OversizedMsg};
            }
            Values Captured{};
            if (!CaptureArguments(Inputs, Captured, std::index_sequence_for<Args...>{}))
            {
                Reset();
                return {Prism::Fault::Code::OversizedMsg};
            }
            const auto Described = DescribeFormatValues(Captured, std::index_sequence_for<Args...>{});
            FormatValidation Validation(Format_, Described, Limits);
            const auto Checked = Validation.Validate();
            if (Checked.Failed()) { Reset(); return Checked; }
            std::construct_at(reinterpret_cast<Values*>(Arguments_.data()), Captured);
            Render_ = &RenderArguments<Values>;
            return {};
        }

        /** @brief 仅在后台线程生成消息；第三方不可恢复异常由该线程入口收口。 */
        [[nodiscard]] auto Render() const -> RenderedMessage
        {
            if (!Render_)
            {
                return {};
            }
            return Render_(*this);
        }

    private:
        template <typename Value>
        static constexpr auto IsText = Text::ViewInput<Value>;
        template <typename Value>
        using SnapshotType = std::conditional_t<IsText<Value>, std::string_view,
            std::remove_cvref_t<Value>>;

        [[nodiscard]] auto CopyText(const std::string_view Text, std::string_view& Output) noexcept -> bool
        {
            if (Text.size() > Storage_.size() - Used_)
            {
                return false;
            }
            if (!Text.empty())
            {
                std::memcpy(Storage_.data() + Used_, Text.data(), Text.size());
            }
            Output = {Storage_.data() + Used_, Text.size()};
            Used_ += Text.size();
            return true;
        }

        template <typename Input, typename Value>
        [[nodiscard]] auto CaptureArgument(Input& Source, Value& Output) noexcept -> bool
        {
            if constexpr (IsText<Input>)
            {
                return CopyText(Text::BorrowView(Source), Output);
            }
            else
            {
                static_assert(std::is_arithmetic_v<Value> || std::same_as<Value, const void*> ||
                    std::same_as<Value, void*> || std::same_as<Value, std::nullptr_t>,
                    "诊断参数须为数值、文本或标准地址值；领域类型先显式取稳定值");
                Output = Source;
                return true;
            }
        }

        template <typename Inputs, typename Values, std::size_t... Indices>
        [[nodiscard]] auto CaptureArguments(Inputs& Sources, Values& ValuesOutput,
            std::index_sequence<Indices...>) noexcept -> bool
        {
            return (CaptureArgument(std::get<Indices>(Sources), std::get<Indices>(ValuesOutput)) && ...);
        }

        template <typename Values>
        [[nodiscard]] static auto RenderArguments(const DeferredMessage& Message) -> RenderedMessage
        {
            const auto& Captured = *std::launder(reinterpret_cast<const Values*>(Message.Arguments_.data()));
            std::array<char, RenderBytes> Storage{};
            FormatOutput Output{Storage};
            std::apply([&](const auto&... Args)
                { std::vformat_to(FormatIterator(Output), std::locale::classic(), Message.Format_,
                    std::make_format_args(Args...)); }, Captured);
            if (Output.Truncated) { Output.Written = Text::FinishTruncatedUtf8(Storage); }
            return {std::string(Storage.data(), Output.Written), Output.Truncated};
        }

        [[nodiscard]] static auto RenderText(const DeferredMessage& Message) -> RenderedMessage
        {
            return {std::string(Message.Format_), false};
        }

        alignas(std::max_align_t) std::array<std::byte, ArgumentBytes> Arguments_{};
        std::array<char, SnapshotBytes> Storage_{};
        std::size_t Used_{0U};
        std::string_view Format_{};
        RenderedMessage (*Render_)(const DeferredMessage&){nullptr};
    };
}
