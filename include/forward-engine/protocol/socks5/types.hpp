#pragma once
#include <string>
#include <cstdint>
#include <forward-engine/protocol/socks5/constants.hpp>

namespace ngx::protocol::socks5
{
    struct target_information
    {
        command cmd;
        address_type atyp;
        std::string host;
        uint16_t port;
    };
}
