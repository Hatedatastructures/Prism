/** @file CarrierCatalog.hpp @brief carrier callback invocation 与 retirement 的私有模板实现。 */
#pragma once

#include <Prism/Composition/Provider/TlsCarrierCatalogOwner.hpp>
#include <Prism/Composition/Recognition/Detail/CarrierFailure.hpp>

#include <type_traits>

namespace Prism::Composition::Provider
{
    template<typename Input>
    auto BoundTlsCarrierCatalog::InvokeOrRetire(
        std::weak_ptr<BoundTlsCarrierCatalog> Weak,
        const std::size_t Index,
        Input Request) -> Net::awaitable<CarrierResult>
    {
        if (auto Owner = Weak.lock())
        {
            co_return co_await Owner->Invoke(Index, std::move(Request));
        }
        co_return co_await RejectInput(
            std::move(Request), CarrierFailure{Prism::Fault::Code::ResourceUnavailable});
    }

    template<typename Input>
    auto BoundTlsCarrierCatalog::Invoke(const std::size_t Index, Input Request)
        -> Net::awaitable<CarrierResult>
    {
        if (!Enter())
        {
            co_return co_await RejectInput(
                std::move(Request), CarrierFailure{Prism::Fault::Code::ResourceUnavailable});
        }
        auto Lease = UseState_ ? UseState_->Acquire()
            : std::expected<Prism::Foundation::GenerationUseLease, CarrierFailure>{
                std::unexpected(CarrierFailure{Prism::Fault::Code::ResourceUnavailable})};
        if (!Lease)
        {
            Leave();
            co_return co_await RejectInput(std::move(Request), Lease.error());
        }
        Invocation Active{shared_from_this(), std::move(*Lease)};
        if (Index >= Entries_.size())
        {
            co_return co_await RejectInput(
                std::move(Request), CarrierFailure{Prism::Fault::Code::InvalidArgument});
        }
        if constexpr (std::is_same_v<Input, Core::CarrierAcceptInput>)
        {
            co_return co_await Entries_[Index].Registration.Accept(std::move(Request));
        }
        else
        {
            co_return co_await Entries_[Index].Registration.AcceptPrepared(std::move(Request));
        }
    }

    template<typename Input>
    auto BoundTlsCarrierCatalog::RejectInput(Input Request, CarrierFailure Cause)
        -> Net::awaitable<CarrierResult>
    {
        CarrierResult Result;
        const auto Failure = co_await Recognition::Detail::RetireCarrierInput(
            std::move(Request.Inbound), Cause);
        Recognition::Detail::SetCarrierFailure(Result, Failure);
        co_return Result;
    }
}
