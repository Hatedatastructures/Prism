set(PrismProtocolProviderLifecycleHeaders
    "${PROJECT_SOURCE_DIR}/Include/Prism/Protocols/ProviderLifecycle/ProviderBindingLifecycle.hpp"
)

PrismAddInterfaceTarget(PrismProtocolProviderLifecycle
    HEADERS ${PrismProtocolProviderLifecycleHeaders}
)
