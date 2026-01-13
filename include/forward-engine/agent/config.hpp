#pragma once

#include <cstdint>
#include <memory/container.hpp>

namespace ngx::agent
{
    struct endpoint
    {
        ngx::memory::string host;
        std::uint16_t port = 0;
    };

    struct limit
    {
        std::uint32_t concurrences = 20U;
        bool blacklist = true;
    };

    struct config
    {
        endpoint positive;
        endpoint addressable;
        ngx::memory::string camouflage;
        limit limit;
        ngx::memory::string cert_path;
        ngx::memory::string key_path;
        bool clash = false;
    };
}
