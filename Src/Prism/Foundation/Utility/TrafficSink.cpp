/**
 * @file TrafficSink.cpp
 * @brief 统计事件提交与退休异常映射实现。
 */
#include <Prism/Foundation/Utility/TrafficSink.hpp>

#include <system_error>
#include <utility>

namespace Prism::Foundation
{
    auto RetireTraffic(std::shared_ptr<TrafficSink> Sink, TrafficRetirement Owner)
        -> boost::asio::awaitable<std::expected<void, Prism::Fault::Failure>>
    {
        using Failure = Prism::Fault::Failure;
        if (!Sink) co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        try
        {
            co_return co_await Sink->Retire(std::move(Owner));
        }
        catch (const std::system_error& Error)
        {
            co_return std::unexpected(Prism::Fault::FromNative(Error.code()));
        }
        catch (...)
        {
            co_return std::unexpected(Failure{Prism::Fault::Code::Blocked});
        }
    }

    auto TrafficObservation::Transfer(const std::size_t Count, const Direction Way) const noexcept -> void
    {
        if (!Sink || Count == 0U)
        {
            return;
        }
        auto Event = Owner;
        Event.Kind = TrafficEventKind::Bytes;
        Event.Up = 0U;
        Event.Down = 0U;
        if (Way == Direction::Upload) Event.Up = Count;
        else Event.Down = Count;
        Sink->Report(Event);
    }

    auto TrafficObservation::Complete(const Prism::Fault::Failure Failure) const noexcept -> void
    {
        if (!Sink)
        {
            return;
        }
        auto Event = Owner;
        Event.Kind = TrafficEventKind::Completed;
        Event.Up = 0U;
        Event.Down = 0U;
        Event.Failure = Failure;
        Sink->Report(Event);
    }
} // namespace Prism::Foundation
