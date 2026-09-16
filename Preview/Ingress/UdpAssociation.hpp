/**
 * @file UdpAssociation.hpp
 * @brief 独立 UDP socket 的 endpoint/association/worker 关联边界。
 * @details 该表只管理关联身份与生命周期，不解析 SOCKS5、VLESS 或其他
 *          应用协议。owner 由表持有，取消回调只执行一次；等待关闭使用
 *          owner-held channel，不使用阻塞锁或轮询。
 */
#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

namespace Preview::Ingress
{

    namespace Net = boost::asio;

    struct UdpAssociationKey final
    {
        Net::ip::udp::endpoint Peer;
        std::uint64_t AssociationId{0};
        std::uint64_t WorkerId{0};

        [[nodiscard]] auto operator==(const UdpAssociationKey &Other) const noexcept -> bool
        {
            return Peer == Other.Peer && AssociationId == Other.AssociationId &&
                   WorkerId == Other.WorkerId;
        }

        [[nodiscard]] auto Valid() const noexcept -> bool
        {
            return AssociationId != 0U;
        }
    };

    struct UdpAssociationKeyHash final
    {
        [[nodiscard]] auto operator()(const UdpAssociationKey &Key) const noexcept -> std::size_t
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

    private:
        [[nodiscard]] static auto Combine(const std::size_t Seed, const std::uint64_t Value) noexcept
            -> std::size_t
        {
            constexpr std::size_t Mix = static_cast<std::size_t>(0x9e3779b97f4a7c15ULL);
            return Seed ^ (std::hash<std::uint64_t>{}(Value) + Mix + (Seed << 6U) + (Seed >> 2U));
        }
    };

    struct UdpAssociationOptions final
    {
        Net::any_io_executor Executor{};
        std::function<void()> Cancel;
    };

    class UdpAssociation final
    {
    public:
        UdpAssociation(UdpAssociationKey KeyValue, UdpAssociationOptions Options)
            : State_(std::make_shared<State>(std::move(KeyValue), std::move(Options)))
        {
        }

        ~UdpAssociation() noexcept
        {
            Close();
        }

        UdpAssociation(const UdpAssociation &) = delete;
        auto operator=(const UdpAssociation &) -> UdpAssociation & = delete;

        [[nodiscard]] auto Key() const noexcept -> const UdpAssociationKey &
        {
            return State_->Key;
        }

        [[nodiscard]] auto Executor() const -> Net::any_io_executor
        {
            return State_->Executor;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return State_->Closed.load(std::memory_order_acquire);
        }

        /**
         * @brief 取消 owner 并唤醒所有关闭等待者。
         * @details 取消回调由 association owner 提供，表和 association
         *          都只允许它成功执行一次。
         */
        auto Close() noexcept -> void
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

        [[nodiscard]] auto WaitClosed() -> Net::awaitable<bool>
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

    private:
        struct State final
        {
            State(UdpAssociationKey KeyValue, UdpAssociationOptions Options)
                : Key(std::move(KeyValue)),
                  Executor(std::move(Options.Executor)),
                  Completion(Executor, 1),
                  Cancel(std::move(Options.Cancel))
            {
            }

            UdpAssociationKey Key;
            Net::any_io_executor Executor;
            Net::experimental::channel<void(boost::system::error_code)> Completion;
            std::function<void()> Cancel;
            std::atomic<bool> Closed{false};
        };

        std::shared_ptr<State> State_;
    };

    using SharedUdpAssociation = std::shared_ptr<UdpAssociation>;

    class UdpAssociationTable final
    {
    public:
        using AssociationMap = std::unordered_map<
            UdpAssociationKey,
            SharedUdpAssociation,
            UdpAssociationKeyHash>;

        UdpAssociationTable() = default;

        ~UdpAssociationTable() noexcept
        {
            Close();
        }

        UdpAssociationTable(const UdpAssociationTable &) = delete;
        auto operator=(const UdpAssociationTable &) -> UdpAssociationTable & = delete;

        [[nodiscard]] auto Register(
            const UdpAssociationKey &Key,
            SharedUdpAssociation Association) -> bool
        {
            if (Draining_ || !Key.Valid() || !Association || Association->Key() != Key ||
                Association->IsClosed())
            {
                return false;
            }
            return Associations_.emplace(Key, std::move(Association)).second;
        }

        [[nodiscard]] auto Find(const UdpAssociationKey &Key) const noexcept
            -> SharedUdpAssociation
        {
            const auto It = Associations_.find(Key);
            return It == Associations_.end() ? nullptr : It->second;
        }

        [[nodiscard]] auto Remove(const UdpAssociationKey &Key) noexcept -> bool
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

        auto Drain() noexcept -> void
        {
            Draining_ = true;
        }

        auto Close() noexcept -> void
        {
            if (Closed_)
            {
                return;
            }
            Closed_ = true;
            Draining_ = true;
            for (const auto &[Key, Association] : Associations_)
            {
                (void)Key;
                if (Association)
                {
                    Association->Close();
                }
            }
            Associations_.clear();
        }

        [[nodiscard]] auto Size() const noexcept -> std::size_t
        {
            return Associations_.size();
        }

        [[nodiscard]] auto IsDraining() const noexcept -> bool
        {
            return Draining_;
        }

        [[nodiscard]] auto IsClosed() const noexcept -> bool
        {
            return Closed_;
        }

    private:
        AssociationMap Associations_;
        bool Draining_{false};
        bool Closed_{false};
    };

} // namespace Preview::Ingress
