#pragma once

#include <string>

#include <Prism/Composition/Builtin/Capability.hpp>
#include <Prism/Foundation/Identifier/Types.hpp>

namespace Prism::Composition::Builtin
{

    /** @brief 将注册表转换为不可变快照时使用的值请求。 */
    struct FreezeRequest
    {
        CapabilitySet RequiredCapabilities{};
        std::string Identity{};
        Prism::GenerationId Generation{};
    };

} // namespace Prism::Composition::Builtin
