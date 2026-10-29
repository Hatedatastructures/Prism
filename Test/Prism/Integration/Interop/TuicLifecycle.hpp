/**
 * @file TuicLifecycle.hpp
 * @brief 等待 TUIC stream chain 中协议连接与 QUIC provider 的关闭完成。
 */
#pragma once

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <expected>
#include <memory>

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Transport/Transmission.hpp>

namespace Prism::Testing::TuicInterop::Detail
{
    namespace Net = boost::asio;

    using DrainResult = std::expected<void, Prism::Fault::Failure>;

    /** @brief 保留关闭链上最先出现的错误。 */
    inline auto PreserveDrainFailure(DrainResult &FirstFailure, DrainResult Candidate) -> void
    {
        if (!Candidate && FirstFailure)
        {
            FirstFailure = std::unexpected(Candidate.error());
        }
    }

    /**
     * @brief 由最外层 owner 关闭 stream，并等待协议连接和底层 adapter 退栈。
     * @details `Lower` 只提供独立的 activity drain；最终关闭仍由 `Owner` 转交，
     *          避免对借用层重复关闭。若 owner 关闭失败，仍等待链上所有可用 activity。
     */
    [[nodiscard]] inline auto CloseAndDrainStreamChain(
        const std::shared_ptr<Prism::Transmission> &Owner,
        const std::shared_ptr<Prism::Transmission> &Lower)
        -> Net::awaitable<DrainResult>
    {
        if (!Owner)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }

        DrainResult FirstFailure{};
        PreserveDrainFailure(FirstFailure, Owner->Close());

        const std::array<std::shared_ptr<Prism::Transmission>, 2> Chain{Owner, Lower};
        for (std::size_t Index = 0; Index < Chain.size(); ++Index)
        {
            const auto &Carrier = Chain[Index];
            if (!Carrier || (Index == 1U && Carrier == Owner))
            {
                continue;
            }
            const auto Activity = Carrier->Activity();
            if (!Activity)
            {
                PreserveDrainFailure(FirstFailure, std::unexpected(
                    Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument}));
                continue;
            }
            PreserveDrainFailure(FirstFailure, co_await Activity->Drain());
        }
        co_return FirstFailure;
    }

    /** @brief 关闭 TUIC Conn，并等待该 Conn 与其被拥有的 stream adapter。 */
    template <class Connection>
    [[nodiscard]] inline auto CloseAndDrainTuicConnection(
        const std::shared_ptr<Connection> &Owner) -> Net::awaitable<DrainResult>
    {
        if (!Owner)
        {
            co_return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        const auto Lower = Owner->Underlying();
        const auto ConnectionOwner = std::static_pointer_cast<Prism::Transmission>(Owner);
        co_return co_await CloseAndDrainStreamChain(ConnectionOwner, Lower);
    }
}
