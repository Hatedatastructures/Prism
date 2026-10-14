/**
 * @file WorkerSessionServices.hpp
 * @brief 冻结每个 worker 的 generation-owned 会话服务值。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Net/Services/WorkerDialService.hpp>
#include <Preview/Runtime/SessionServices.hpp>
#include <Preview/Runtime/WorkerGroup.hpp>

#include <boost/asio/awaitable.hpp>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace Preview::Application
{

    namespace Net = boost::asio;

    struct WorkerSessionServicesPreparation final
    {
        Preview::Runtime::SharedSessionServices Base;
        Preview::Runtime::WorkerGroup *Workers{nullptr};
        std::span<const std::shared_ptr<Preview::Network::Services::WorkerDialService>> Dials;
    };

    [[nodiscard]] inline auto ConnectWorkerDial(
        std::shared_ptr<Preview::Network::Services::WorkerDialService> Dial,
        const Preview::Network::Target &Target)
        -> Net::awaitable<std::expected<Preview::SharedTransmission, Preview::Fault::Failure>>
    {
        co_return co_await Dial->Connect(Target);
    }

    [[nodiscard]] inline auto MakeWorkerSessionServices(
        WorkerSessionServicesPreparation Request)
        -> std::expected<std::vector<Preview::Runtime::SessionServices>, Preview::Fault::Failure>
    {
        if (!Request.Base || !Request.Workers || Request.Dials.empty() ||
            Request.Dials.size() != Request.Workers->Size())
        {
            return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
        }
        std::vector<Preview::Runtime::SessionServices> Services;
        Services.reserve(Request.Dials.size());
        for (std::size_t Index = 0; Index < Request.Dials.size(); ++Index)
        {
            const auto WorkerId = Preview::WorkerId{static_cast<std::uint64_t>(Index + 1U)};
            const auto *Worker = Request.Workers->Find(WorkerId);
            if (!Worker || !Worker->Resources().Bytes || !Request.Dials[Index])
            {
                return std::unexpected(Preview::Fault::Failure{Preview::Fault::Code::Blocked});
            }
            auto WorkerServices = *Request.Base;
            WorkerServices.Bytes = Worker->Resources().Bytes;
            WorkerServices.Dial = std::bind_front(&ConnectWorkerDial, Request.Dials[Index]);
            Services.push_back(std::move(WorkerServices));
        }
        return Services;
    }

} // namespace Preview::Application
