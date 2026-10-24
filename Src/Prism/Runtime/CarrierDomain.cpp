/** @file CarrierDomain.cpp @brief 载体执行域证据校验实现。 */
#include <Prism/Runtime/CarrierDomain.hpp>

#include <utility>

namespace Prism::Runtime
{
    CarrierDomain::CarrierDomain(
        boost::asio::any_io_executor Executor,
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity)
        : Executor_(std::move(Executor)), Activity_(std::move(Activity))
    {
    }

    auto CarrierDomain::Create(
        boost::asio::any_io_executor Executor,
        std::shared_ptr<Prism::Contract::CarrierActivity> Activity)
        -> std::expected<CarrierDomain, Prism::Fault::Failure>
    {
        if (!Executor)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        if (Activity && Activity->Executor() != Executor)
        {
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        return CarrierDomain(std::move(Executor), std::move(Activity));
    }
}
