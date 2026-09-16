#pragma once

#include <functional>

#include <Preview/Composition/Builtin/Capability.hpp>
#include <Preview/Foundation/Cancellation/Mode.hpp>
#include <Preview/Foundation/Error/Expected.hpp>
#include <Preview/Foundation/Executor/Affinity.hpp>
#include <Preview/Foundation/Identifier/Types.hpp>
#include <Preview/Foundation/Memory/Domain.hpp>

namespace Preview::Composition::Builtin
{

    /** @brief 单次 builtin 回调接收的值请求。 */
    struct BuiltinRequest
    {
        Preview::BuiltinId Id{};
        Preview::GenerationId Generation{};
        CapabilitySet Capabilities{};
        Preview::Memory::Domain MemoryDomain{Preview::Memory::Domain::Request};
        Preview::Executor::Affinity ExecutorAffinity{Preview::Executor::Affinity::Any};
        Preview::Cancellation::Mode CancellationMode{Preview::Cancellation::Mode::None};
    };

    using Request = BuiltinRequest;
    using Options = BuiltinRequest;
    using BuiltinCallback = std::function<Preview::Foundation::Expected<void>(const BuiltinRequest &)>;
    using Callback = BuiltinCallback;

    /** @brief 一个静态 builtin 的元数据和无 I/O 回调。 */
    struct BuiltinDescriptor
    {
        Preview::KindId Kind{};
        Preview::NameId Name{};
        CapabilitySet Provides{};
        CapabilitySet Requires{};
        Preview::Memory::Domain MemoryDomain{Preview::Memory::Domain::Global};
        Preview::Executor::Affinity ExecutorAffinity{Preview::Executor::Affinity::Any};
        Preview::Cancellation::Mode CancellationMode{Preview::Cancellation::Mode::None};
        BuiltinCallback Callback{};
    };

    using BuiltinOptions = BuiltinDescriptor;

    /** @brief 快照内的注册项，只有注册表可分配 Id。 */
    struct RegisteredBuiltin
    {
        Preview::BuiltinId Id{};
        BuiltinDescriptor Descriptor{};
    };

    /** @brief 选择快照内某个 builtin 的单参数对象。 */
    struct InvocationRequest
    {
        Preview::BuiltinId Id{};
    };

} // namespace Preview::Composition::Builtin
