/**
 * @file SessionAdmission.hpp
 * @brief listener 向应用会话工厂移交的一次 owning admission。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Generation/Lifetime.hpp>
#include <Preview/Foundation/Identifier/Id.hpp>
#include <Preview/Transport/Transmission.hpp>

#include <expected>
#include <memory>
#include <string>

namespace Preview::Runtime
{

    class Session;

    /** @brief 同一代次发布 pin、worker 身份和入站传输的会话准入输入。 */
    struct SessionAdmission final
    {
        Preview::SharedTransmission Inbound;
        Preview::WorkerId Worker{};
        std::string SourceIp;
        Preview::Foundation::GenerationPin Generation;
    };

    using SessionAdmissionResult =
        std::expected<std::shared_ptr<Session>, Preview::Fault::Failure>;

} // namespace Preview::Runtime
