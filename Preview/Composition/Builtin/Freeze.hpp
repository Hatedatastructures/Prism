#pragma once

#include <string>

#include <Preview/Composition/Builtin/Capability.hpp>
#include <Preview/Foundation/Identifier/Types.hpp>

namespace Preview::Composition::Builtin
{

    /** @brief 将注册表转换为不可变快照时使用的值请求。 */
    struct FreezeRequest
    {
        CapabilitySet RequiredCapabilities{};
        std::string Identity{};
        Preview::GenerationId Generation{};
    };

} // namespace Preview::Composition::Builtin
