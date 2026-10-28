/**
 * @file Binding.hpp
 * @brief TUIC 私有 admission 服务绑定声明。
 */
#pragma once

#include <Prism/Protocols/Tuic/Admission.hpp>
#include <Prism/Contract/Services/Quic.hpp>

#include <string>

namespace Prism::Tuic
{

    /** @brief 为单条 TUIC connection 建立 owning admission 服务。 */
    [[nodiscard]] auto BindServices(
        Prism::Contract::QuicBindingServices Services,
        std::string SourceIp) -> AdmissionServices;

} // namespace Prism::Tuic
