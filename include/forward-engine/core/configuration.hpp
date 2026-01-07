#pragma once

#include <agent/config.hpp>
#include <trace/config.hpp>

namespace ngx::core
{
    struct configuration 
    {
        agent::config agent;
        trace::config trace;
    };
}