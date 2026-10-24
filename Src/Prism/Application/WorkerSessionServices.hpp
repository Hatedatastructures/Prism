/** @file WorkerSessionServices.hpp @brief 每个 worker 的 generation-owned 会话服务准备接口。 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <span>
#include <vector>

namespace Prism::Application
{

    namespace Net = boost::asio;

    struct WorkerSessionServicesPreparation final
    {
        Prism::Runtime::SharedSessionServices Base;
        Prism::Runtime::WorkerGroup *Workers{nullptr};
        std::span<const std::shared_ptr<Prism::Network::Services::WorkerDialService>> Dials;
    };

    [[nodiscard]] auto ConnectWorkerDial(
        std::shared_ptr<Prism::Network::Services::WorkerDialService> Dial,
        const Prism::Network::Target &Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>;

    [[nodiscard]] auto MakeWorkerSessionServices(WorkerSessionServicesPreparation Request)
        -> std::expected<std::vector<Prism::Runtime::SessionServices>, Prism::Fault::Failure>;

} // namespace Prism::Application
