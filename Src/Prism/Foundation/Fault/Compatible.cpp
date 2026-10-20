/**
 * @file Compatible.cpp
 * @brief Fault 分类错误消息缓存实现。
 */
#include <Prism/Foundation/Fault/Compatible.hpp>

#include <array>

namespace Prism::Fault
{
    auto CachedMessage(const Code C) noexcept -> const std::string&
    {
        constexpr auto CodeCount = static_cast<std::size_t>(Code::Count);
        static const auto Messages = []()
        {
            std::array<std::string, CodeCount + 1> MessageEntries{};
            for (std::size_t I = 0; I < CodeCount; ++I)
            {
                MessageEntries[I] = std::string(Describe(static_cast<Code>(I)));
            }
            MessageEntries[CodeCount] = "unknown";
            return MessageEntries;
        }();

        if (const auto Index = static_cast<std::size_t>(C); Index < CodeCount)
        {
            return Messages[Index];
        }
        return Messages[CodeCount];
    }

    auto FaultCategory::message(const int ErrorValue) const -> std::string
    {
        return CachedMessage(static_cast<Code>(ErrorValue));
    }
} // namespace Prism::Fault

namespace boost::system
{
    auto FaultCategory::message(const int ErrorValue) const -> std::string
    {
        return Prism::Fault::CachedMessage(static_cast<Prism::Fault::Code>(ErrorValue));
    }
} // namespace boost::system
