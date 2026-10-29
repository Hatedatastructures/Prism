/**
 * @file Compare.hpp
 * @brief Preview Mailbox 旧实现基线命令行选项。
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace Prism::Runtime::Perf
{

    struct Options final
    {
        std::size_t Producers{1};
        std::size_t Capacity{1024};
        std::size_t Commands{100000};
        std::size_t Rounds{5};
        std::uint64_t Seed{0xC01A'0001ull};
        bool ValidateOnly{false};
    };

} // namespace Prism::Runtime::Perf
