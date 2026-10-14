/**
 * @file ResolverCacheResults.hpp
 * @brief Resolver 缓存与独占返回地址列表之间的转换 owner。
 * @details 调用者在 Resolver 串行 executor 上访问缓存；返回地址列表借用有界池，租约随列表存活。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Net/Dns/AddressList.hpp>
#include <Preview/Net/Dns/Cache.hpp>

#include <chrono>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <utility>

namespace Preview::Network::Dns::Detail
{
    /** @brief Resolver 缓存转换 owner 的实际资源与策略快照。 */
    struct ResolverCacheView final
    {
        Cache &CacheOwner;
        Memory::BytePool &Pool;
        bool CacheEnabled;
        bool NegativeOnTimeout;
        std::uint64_t &HitCount;
    };

    /**
     * @brief 在缓存事实与独占 typed 解析输出之间执行有界转换。
     * @details 不拥有 Cache 或 Pool，不切换 executor；ResolverState 保证调用发生在其串行 executor。
     */
    class ResolverCacheResults final
    {
    public:
        explicit ResolverCacheResults(ResolverCacheView View) noexcept
            : Cache_(View.CacheOwner), Pool_(View.Pool), CacheEnabled_(View.CacheEnabled),
              NegativeOnTimeout_(View.NegativeOnTimeout), HitCount_(View.HitCount)
        {
        }

        /** @brief 把同步地址范围写入本次调用独占的有界地址列表。 */
        template <typename AddressRange>
        [[nodiscard]] auto MakeAddressList(const AddressRange &Addresses)
            -> std::expected<AddressList, Preview::Fault::Failure>
        {
            AddressList Result;
            for (const auto &Address : Addresses)
            {
                const auto Appended = Result.TryAppend(Address, Pool_);
                if (!Appended)
                {
                    return std::unexpected(Appended.error());
                }
            }
            return Result;
        }

        /** @brief 读取正/负缓存；负命中是 DnsFailed typed failure，未命中为 nullopt。 */
        [[nodiscard]] auto Read(const std::string &Name)
            -> std::optional<std::expected<AddressList, Preview::Fault::Failure>>
        {
            if (!CacheEnabled_)
            {
                return std::nullopt;
            }
            auto Cached = Cache_.Get(Name, static_cast<std::uint16_t>(QType::A));
            if (!Cached)
            {
                return std::nullopt;
            }
            ++HitCount_;
            if (Cached->empty())
            {
                return std::expected<AddressList, Preview::Fault::Failure>{
                    std::unexpected(Preview::Fault::Failure{
                        Preview::Fault::Code::DnsFailed, {}})};
            }
            return MakeAddressList(*Cached);
        }

        /** @brief 按正缓存 TTL 策略存储地址值，不保留输入引用或返回列表。 */
        template <typename AddressRange>
        auto StorePositive(const std::string &Name, const AddressRange &Addresses,
                           const std::chrono::seconds Ttl) -> void
        {
            if (!CacheEnabled_ || Ttl <= std::chrono::seconds::zero())
            {
                return;
            }
            PutInput Input;
            Input.Domain = Name;
            Input.QType = static_cast<std::uint16_t>(QType::A);
            Input.Ips.assign(Addresses.begin(), Addresses.end());
            Input.Ttl = Ttl;
            Cache_.Put(Input);
        }

        /** @brief 写负缓存；配置禁止缓存超时时保留下一次真实重试机会。 */
        auto StoreNegative(const std::string &Name,
                           const Preview::Fault::Failure &Failure) -> void
        {
            if (!CacheEnabled_ ||
                (!NegativeOnTimeout_ && Failure.Code == Preview::Fault::Code::Timeout))
            {
                return;
            }
            Cache_.PutNegative(Name, static_cast<std::uint16_t>(QType::A));
        }

    private:
        Cache &Cache_;
        Memory::BytePool &Pool_;
        bool CacheEnabled_;
        bool NegativeOnTimeout_;
        std::uint64_t &HitCount_;
    };
} // namespace Preview::Network::Dns::Detail
