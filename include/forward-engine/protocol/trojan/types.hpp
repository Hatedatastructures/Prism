#pragma once
#include <string>
#include <cstdint>
#include <forward-engine/protocol/trojan/constants.hpp>

namespace ngx::protocol::trojan
{
    struct target_information
    {
        command cmd;
        address_type atyp;
        std::string host;
        uint16_t port;
    };
}
