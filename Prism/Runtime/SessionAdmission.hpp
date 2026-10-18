/**
 * @file SessionAdmission.hpp
 * @brief listener 向应用会话工厂移交的一次 owning admission。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Foundation/Generation/Lifetime.hpp>
#include <Prism/Foundation/Identifier/Id.hpp>
#include <Prism/Transport/Transmission.hpp>

#include <expected>
#include <memory>
#include <string>

namespace Prism::Runtime
{

    class Session;

    /** @brief 同一代次发布 pin、worker 身份和入站传输的会话准入输入。 */
    struct SessionAdmission final
    {
        Prism::SharedTransmission Inbound;
        Prism::WorkerId Worker{};
        std::string SourceIp;
        Prism::Foundation::GenerationPin Generation;
    };

    using SessionAdmissionResult =
        std::expected<std::shared_ptr<Session>, Prism::Fault::Failure>;

} // namespace Prism::Runtime
