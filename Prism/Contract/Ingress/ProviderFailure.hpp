/** @file ProviderFailure.hpp @brief 实例准备和绑定失败；错误路径不得包含凭据。 */
#pragma once
#include <string>
namespace Prism::Contract
{
    enum class ProviderError { InvalidConfiguration, MissingAuthentication, MissingResolver,
        MissingSender, InvalidCredential, GenerationMismatch, Cancelled, AlreadyFrozen, AlreadyBound,
        DuplicateInstance, UnsupportedInstance, MissingTls, MissingHttp3, MissingExporter,
        MissingEgress, AmbiguousListener, DispatchUnavailable };
    struct ProviderFailure final
    {
        ProviderError Code;
        std::string Instance;
        std::string Path;
    };
}
