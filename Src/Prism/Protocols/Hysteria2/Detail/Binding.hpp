/**
 * @file Binding.hpp
 * @brief Hysteria2 私有 admission 服务绑定声明。
 */
#pragma once

#include <Prism/Protocols/Hysteria2/Admission.hpp>
#include <Prism/Contract/Services/Quic.hpp>

namespace Prism::Hysteria2
{

    /** @brief 为单条 Hysteria2 connection 建立 owning admission 服务。 */
    [[nodiscard]] auto BindServices(Prism::Contract::QuicBindingServices Services)
        -> AdmissionServices;

} // namespace Prism::Hysteria2
