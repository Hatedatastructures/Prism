/** @file Throttle.cpp @brief 限速与远端失败封禁中间件实现。 */
#include <Prism/Runtime/Middleware/Builtin/Throttle.hpp>

#include <Prism/Foundation/Utility/Rate/TokenBucket.hpp>
#include <Prism/Runtime/Middleware/Context.hpp>

#include <boost/asio/dispatch.hpp>
#include <boost/asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <string_view>

namespace Prism::Middleware::Builtin
{
    auto ThrottleMiddleware::Handle(Prism::SharedTransmission & /*Inbound*/, Context & /*ctx*/)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        if (!Bucket_)
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::NotSupported};
        }
        std::uint64_t Now = 0;
        if (NowFn_)
        {
            Now = NowFn_();
        }
        else
        {
            Now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch())
                    .count());
        }
        if (!Bucket_->TryTake(1, Now))
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        }
        co_return Prism::Fault::Failure{};
    }

    auto BanMiddleware::Handle(Prism::SharedTransmission & /*Inbound*/, Context &ctx)
        -> Net::awaitable<Prism::Fault::Failure>
    {
        const std::string_view Source = ctx.SourceIp.empty()
            ? std::string_view{"unknown"} : std::string_view{ctx.SourceIp};
        const auto KeyLength = Source.size();
        std::array<char, MaximumKeyBytes> KeyStorage{};
        if (KeyLength > KeyStorage.size())
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
        }
        std::copy(Source.begin(), Source.end(), KeyStorage.begin());
        co_await Net::dispatch(Owner_, Net::use_awaitable);
        if (!IsValidOptions())
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
        }
        const auto Now = NowMilliseconds();
        PruneExpired(Now);
        const std::string_view Key{KeyStorage.data(), KeyLength};
        const auto *Entry = Find(Key);
        if (Entry && Entry->Banned)
            co_return Prism::Fault::Failure{Prism::Fault::Code::Blocked};
        co_return Prism::Fault::Failure{};
    }

    auto BanMiddleware::RecordFailure(std::string_view Key) -> Net::awaitable<Prism::Fault::Failure>
    {
        std::array<char, MaximumKeyBytes> KeyStorage{};
        if (Key.empty())
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
        }
        if (Key.size() > KeyStorage.size())
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
        }
        const auto KeyLength = Key.size();
        std::copy(Key.begin(), Key.end(), KeyStorage.begin());
        co_await Net::dispatch(Owner_, Net::use_awaitable);
        if (!IsValidOptions())
        {
            co_return Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument};
        }
        const auto Now = NowMilliseconds();
        PruneExpired(Now);
        const std::string_view StoredKey{KeyStorage.data(), KeyLength};
        auto *Entry = Find(StoredKey);
        if (!Entry)
        {
            Entry = FindFree();
            if (!Entry)
                co_return Prism::Fault::Failure{Prism::Fault::Code::ResourceUnavailable};
            Entry->Occupied = true;
            Entry->KeyLength = KeyLength;
            std::copy_n(KeyStorage.begin(), KeyLength, Entry->Key.begin());
            Entry->WindowStartedAt = Now;
        }
        if (Elapsed(Now, Entry->WindowStartedAt) >= Options_.WindowMs)
        {
            Entry->FailureCount = 0;
            Entry->WindowStartedAt = Now;
            Entry->Banned = false;
        }
        if (Entry->FailureCount < Options_.MaxFailures)
            ++Entry->FailureCount;
        Entry->LastFailureAt = Now;
        if (Entry->FailureCount >= Options_.MaxFailures)
        {
            Entry->Banned = true;
            Entry->BannedAt = Now;
        }
        co_return Prism::Fault::Failure{};
    }

    auto BanMiddleware::IsValidOptions() const noexcept -> bool
    {
        return Options_.MaxFailures != 0 && Options_.WindowMs != 0;
    }

    auto BanMiddleware::NowMilliseconds() noexcept -> std::uint64_t
    {
        return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    auto BanMiddleware::Elapsed(const std::uint64_t Now, const std::uint64_t Since) noexcept
        -> std::uint64_t
    {
        return Now >= Since ? Now - Since : 0;
    }

    auto BanMiddleware::PruneExpired(const std::uint64_t Now) noexcept -> void
    {
        for (auto &Entry : Entries_)
        {
            if (!Entry.Occupied)
                continue;
            const auto Since = Entry.Banned ? Entry.BannedAt : Entry.LastFailureAt;
            if (Elapsed(Now, Since) >= Options_.WindowMs)
                Entry = {};
        }
    }

    auto BanMiddleware::Find(const std::string_view Key) noexcept -> Entry *
    {
        for (auto &Entry : Entries_)
        {
            if (Entry.Occupied && Entry.KeyLength == Key.size() &&
                std::equal(Key.begin(), Key.end(), Entry.Key.begin()))
                return &Entry;
        }
        return nullptr;
    }

    auto BanMiddleware::FindFree() noexcept -> Entry *
    {
        for (auto &Entry : Entries_)
            if (!Entry.Occupied)
                return &Entry;
        return nullptr;
    }
}
