/**
 * @file WorkerSessionServices.hpp
 * @brief 冻结每个 worker 的 generation-owned 会话服务值。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Net/Services/WorkerDialService.hpp>
#include <Prism/Runtime/SessionServices.hpp>
#include <Prism/Runtime/WorkerGroup.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <utility>
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

    [[nodiscard]] inline auto ConnectWorkerDial(
        std::shared_ptr<Prism::Network::Services::WorkerDialService> Dial,
        const Prism::Network::Target &Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        co_return co_await Dial->Connect(Target);
    }

    [[nodiscard]] inline auto MakeWorkerSessionServices(
        WorkerSessionServicesPreparation Request)
        -> std::expected<std::vector<Prism::Runtime::SessionServices>, Prism::Fault::Failure>
    {
        if (!Request.Base || !Request.Workers || Request.Dials.empty() ||
            Request.Dials.size() != Request.Workers->Size())
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
        }
        std::vector<Prism::Runtime::SessionServices> Services;
        Services.reserve(Request.Dials.size());
        for (std::size_t Index = 0; Index < Request.Dials.size(); ++Index)
        {
            const auto WorkerId = Prism::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            const auto *Worker = Request.Workers->Find(WorkerId);
            if (!Worker || !Worker->Resources().Bytes || !Request.Dials[Index])
            {
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            }
            auto WorkerServices = *Request.Base;
            WorkerServices.Bytes = Worker->Resources().Bytes;
            WorkerServices.Dial = std::bind_front(&ConnectWorkerDial, Request.Dials[Index]);
            Services.push_back(std::move(WorkerServices));
        }
        return Services;
    }

} // namespace Prism::Application
