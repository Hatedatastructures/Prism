#pragma once

#include "deviant.hpp"

namespace ngx::abnormal
{
    /**
     * @brief 网络异常
     * @details 网络异常是指在程序运行过程中，由于网络原因而导致的异常情况。
     */
    class network : public exception
    {
    public:
        template <typename... Args>
        explicit network(std::format_string<Args...> fmt, Args&&... args)
            : exception(std::source_location::current(), fmt, std::forward<Args>(args)...)
        {}

        template <typename... Args>
        explicit network(const std::source_location& loc, std::format_string<Args...> fmt, Args&&... args)
            : exception(loc, fmt, std::forward<Args>(args)...)
        {}

        explicit network(const std::string& msg,
                               const std::source_location& loc = std::source_location::current())
            : exception(loc, msg)
        {}

    protected:
        std::string_view type_name() const noexcept override { return "NETWORK"; }
    };
}
