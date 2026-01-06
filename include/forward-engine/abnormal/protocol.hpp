#pragma once

#include "deviant.hpp"

namespace ngx::abnormal
{
    /**
     * @brief 协议异常
     * @details 协议异常是指在程序运行过程中，由于协议错误而导致的异常情况。
     */
    class protocol : public exception
    {
    public:
        template <typename... Args>
        explicit protocol(std::format_string<Args...> fmt, Args&&... args)
            : exception(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {}

        template <typename... Args>
        explicit protocol(const std::source_location& loc, std::format_string<Args...> fmt, Args&&... args)
            : exception(loc, fmt, std::forward<Args>(args)...)
        {}

        explicit protocol(const std::string& msg,
                                const std::source_location& loc = std::source_location::current())
            : exception(loc, msg)
        {}

    protected:
        std::string_view type_name() const noexcept override { return "PROTOCOL"; }
    };
}
