/**
 * @file DeferredMessage.cpp
 * @brief 固定快照消息的非模板存储操作。
 */
#include <Prism/Foundation/Utility/Diagnose/Submission/Message.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace Prism::Diagnose::Detail
{
    auto FormatIterator::operator=(const char Value) noexcept -> FormatIterator&
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

    auto DeferredMessage::Reset() noexcept -> void
    {
        const Crypto::SecretScope TextCleanup(std::span(
            reinterpret_cast<std::uint8_t*>(Storage_.data()), Used_));
        const Crypto::SecretScope ArgumentCleanup(std::span(
            reinterpret_cast<std::uint8_t*>(Arguments_.data()), Arguments_.size()));
        Used_ = 0U;
        Format_ = {};
        Render_ = nullptr;
    }

    auto DeferredMessage::CaptureText(const std::string_view Text, const FormattingLimits& Limits) noexcept
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

    auto DeferredMessage::CopyText(const std::string_view Text, std::string_view& Output) noexcept -> bool
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
}
