#include <forward-engine/agent/handler.hpp>

namespace ngx::agent
{
    auto registry::instantiation() -> registry &
    {
        static registry instance;
        static bool inited = false;
        if (!inited)
        {
            ngx::trace::debug("Registry instantiated at address: {}", (void *)&instance);
            inited = true;
        }
        return instance;
    }
} // namespace ngx::agent