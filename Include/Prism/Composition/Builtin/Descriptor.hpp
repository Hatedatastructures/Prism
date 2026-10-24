#pragma once

#include <functional>

#include <Prism/Composition/Builtin/Capability.hpp>
#include <Prism/Foundation/Cancellation/Mode.hpp>
#include <Prism/Foundation/Error/Expected.hpp>
#include <Prism/Foundation/Executor/Affinity.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Foundation/Memory/Domain.hpp>

namespace Prism::Composition::Builtin
{

    /** @brief 单次 builtin 回调接收的值请求。 */
    struct BuiltinRequest
    {
        Prism::BuiltinId Id{};
        Prism::GenerationId Generation{};
        CapabilitySet Capabilities{};
        Prism::Memory::Domain MemoryDomain{Prism::Memory::Domain::Request};
        Prism::Executor::Affinity ExecutorAffinity{Prism::Executor::Affinity::Any};
        Prism::Cancellation::Mode CancellationMode{Prism::Cancellation::Mode::None};
    };

    using Request = BuiltinRequest;
    using Options = BuiltinRequest;
    using BuiltinCallback = std::function<Prism::Foundation::Expected<void>(const BuiltinRequest &)>;
    using Callback = BuiltinCallback;

    /** @brief 一个静态 builtin 的元数据和无 I/O 回调。 */
    struct BuiltinDescriptor
    {
        Prism::KindId Kind{};
        Prism::NameId Name{};
        CapabilitySet Provides{};
        CapabilitySet Requires{};
        Prism::Memory::Domain MemoryDomain{Prism::Memory::Domain::Global};
        Prism::Executor::Affinity ExecutorAffinity{Prism::Executor::Affinity::Any};
        Prism::Cancellation::Mode CancellationMode{Prism::Cancellation::Mode::None};
        BuiltinCallback Callback{};
    };

    using BuiltinOptions = BuiltinDescriptor;

    /** @brief 快照内的注册项，只有注册表可分配 Id。 */
    struct RegisteredBuiltin
    {
        Prism::BuiltinId Id{};
        BuiltinDescriptor Descriptor{};
    };

    /** @brief 选择快照内某个 builtin 的单参数对象。 */
    struct InvocationRequest
    {
        Prism::BuiltinId Id{};
    };

} // namespace Prism::Composition::Builtin
