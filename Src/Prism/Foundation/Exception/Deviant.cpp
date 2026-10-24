/**
 * @file Deviant.cpp
 * @brief 结构化异常消息与源码位置实现。
 */
#include <Prism/Foundation/Exception/Deviant.hpp>

#include <filesystem>

namespace Prism::Exception
{
    Deviant::Deviant(std::error_code ErrorCode, const std::string_view Description,
        const std::source_location& SourceLocation)
        : std::runtime_error(CreateWhat(ErrorCode, Description)), Ec_(ErrorCode), Location_(SourceLocation)
    {
    }

    Deviant::Deviant(const std::string& Message, const std::source_location& SourceLocation)
        : Deviant(std::error_code(static_cast<int>(Fault::Code::GenericError), Fault::Category()), Message,
            SourceLocation)
    {
    }

    auto Deviant::Filename() const -> std::string
    {
        return std::filesystem::path(Location_.file_name()).filename().string();
    }

    auto Deviant::Dump() const -> std::string
    {
        return std::format("[{}:{}] [{}:{}] {}", Filename(), Location_.line(), TypeName(), Ec_.value(),
            std::runtime_error::what());
    }

    auto Deviant::CreateWhat(const std::error_code& ErrorCode,
        const std::string_view Description) -> std::string
    {
        if (Description.empty())
        {
            return ErrorCode.message();
        }
        return std::format("{}: {}", ErrorCode.message(), Description);
    }
} // namespace Prism::Exception
