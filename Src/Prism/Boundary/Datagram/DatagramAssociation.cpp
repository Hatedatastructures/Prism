/** @file DatagramAssociation.cpp @brief UDP association 与关联表生命周期实现。 */
#include <Prism/Boundary/Datagram/DatagramAssociation.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

namespace Prism::Boundary
{
    auto DatagramAssociationKey::operator==(const DatagramAssociationKey& Other) const noexcept -> bool
    {
        return Peer == Other.Peer && AssociationId == Other.AssociationId && WorkerId == Other.WorkerId;
    }

    auto DatagramAssociationKey::Valid() const noexcept -> bool
    {
        return AssociationId != 0U;
    }

    auto DatagramAssociationKeyHash::operator()(const DatagramAssociationKey& Key) const noexcept
        -> std::size_t
    {
        std::size_t Hash = std::hash<std::uint64_t>{}(Key.AssociationId);
        Hash = Combine(Hash, Key.WorkerId);
        const auto Address = Key.Peer.address();
        if (Address.is_v4())
        {
            Hash = Combine(Hash, Address.to_v4().to_uint());
        }
        else
        {
            for (const auto Byte : Address.to_v6().to_bytes())
            {
                Hash = Combine(Hash, Byte);
            }
        }
        return Combine(Hash, Key.Peer.port());
    }

    auto DatagramAssociationKeyHash::Combine(const std::size_t Seed,
        const std::uint64_t Value) noexcept -> std::size_t
    {
        constexpr std::size_t Mix = static_cast<std::size_t>(0x9e3779b97f4a7c15ULL);
        return Seed ^ (std::hash<std::uint64_t>{}(Value) + Mix + (Seed << 6U) + (Seed >> 2U));
    }

    struct DatagramAssociation::State final
    {
        State(DatagramAssociationKey KeyValue, DatagramAssociationOptions Options)
            : Key(std::move(KeyValue)), Executor(std::move(Options.Executor)),
              Completion(Executor, 1), Cancel(std::move(Options.Cancel))
        {
        }

        DatagramAssociationKey Key;
        Net::any_io_executor Executor;
        Net::experimental::channel<void(boost::system::error_code)> Completion;
        std::function<void()> Cancel;
        std::atomic<bool> Closed{false};
    };

    DatagramAssociation::DatagramAssociation(DatagramAssociationKey KeyValue,
        DatagramAssociationOptions Options)
        : State_(std::make_shared<State>(std::move(KeyValue), std::move(Options)))
    {
    }

    DatagramAssociation::~DatagramAssociation() noexcept
    {
        Close();
    }

    auto DatagramAssociation::Key() const noexcept -> const DatagramAssociationKey&
    {
        return State_->Key;
    }

    auto DatagramAssociation::Executor() const -> Net::any_io_executor
    {
        return State_->Executor;
    }

    auto DatagramAssociation::IsClosed() const noexcept -> bool
    {
        return State_->Closed.load(std::memory_order_acquire);
    }

    auto DatagramAssociation::Close() noexcept -> void
    {
        const auto State = State_;
        if (State->Closed.exchange(true, std::memory_order_acq_rel))
        {
            return;
        }
        if (State->Cancel)
        {
            try
            {
                State->Cancel();
            }
            catch (...)
            {
                // owner 取消异常不能逃出 ingress 生命周期。
            }
        }
        (void)State->Completion.try_send(boost::system::error_code{});
    }

    auto DatagramAssociation::WaitClosed() -> Net::awaitable<bool>
    {
        const auto State = State_;
        co_await Net::dispatch(State->Executor, Net::use_awaitable);
        if (State->Closed.load(std::memory_order_acquire))
        {
            co_return true;
        }
        boost::system::error_code Error;
        co_await State->Completion.async_receive(Net::redirect_error(Net::use_awaitable, Error));
        co_return !Error || State->Closed.load(std::memory_order_acquire);
    }

    DatagramAssociationTable::~DatagramAssociationTable() noexcept
    {
        Close();
    }

    auto DatagramAssociationTable::Register(const DatagramAssociationKey& Key,
        SharedDatagramAssociation Association) -> bool
    {
        if (Draining_ || !Key.Valid() || !Association || Association->Key() != Key ||
            Association->IsClosed())
        {
            return false;
        }
        return Associations_.emplace(Key, std::move(Association)).second;
    }

    auto DatagramAssociationTable::Find(const DatagramAssociationKey& Key) const noexcept
        -> SharedDatagramAssociation
    {
        const auto It = Associations_.find(Key);
        return It == Associations_.end() ? nullptr : It->second;
    }

    auto DatagramAssociationTable::Remove(const DatagramAssociationKey& Key) noexcept -> bool
    {
        const auto It = Associations_.find(Key);
        if (It == Associations_.end())
        {
            return false;
        }
        if (It->second)
        {
            It->second->Close();
        }
        Associations_.erase(It);
        return true;
    }

    auto DatagramAssociationTable::Drain() noexcept -> void
    {
        Draining_ = true;
    }

    auto DatagramAssociationTable::Close() noexcept -> void
    {
        if (Closed_)
        {
            return;
        }
        Closed_ = true;
        Draining_ = true;
        for (const auto& [Key, Association] : Associations_)
        {
            (void)Key;
            if (Association)
            {
                Association->Close();
            }
        }
        Associations_.clear();
    }

    auto DatagramAssociationTable::Size() const noexcept -> std::size_t
    {
        return Associations_.size();
    }

    auto DatagramAssociationTable::IsDraining() const noexcept -> bool
    {
        return Draining_;
    }

    auto DatagramAssociationTable::IsClosed() const noexcept -> bool
    {
        return Closed_;
    }
}
