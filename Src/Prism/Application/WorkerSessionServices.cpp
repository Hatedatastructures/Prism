/** @file WorkerSessionServices.cpp @brief 冻结每个 worker 独立的会话服务值。 */

#include <Prism/Application/WorkerSessionServices.hpp>

#include <utility>

namespace Prism::Application
{

    auto ConnectWorkerDial(
        std::shared_ptr<Prism::Network::Services::WorkerDialService> Dial,
        const Prism::Network::Target &Target)
        -> Net::awaitable<std::expected<Prism::SharedTransmission, Prism::Fault::Failure>>
    {
        co_return co_await Dial->Connect(Target);
    }

    auto MakeWorkerSessionServices(WorkerSessionServicesPreparation Request)
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
