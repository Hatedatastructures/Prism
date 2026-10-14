/** @file FamilyMerge.hpp @brief DNS 双族结果的唯一地址事实合并与顺序去重。 */
#pragma once
#include <Preview/Foundation/Fault/Compatible.hpp>
#include <Preview/Foundation/Memory/BytePool.hpp>
#include <Preview/Net/Dns/Types.hpp>
#include <algorithm>
#include <utility>

namespace Preview::Network::Dns::Detail
{
    /** @brief A/AAAA 合并的拥有型输入；Pool 只为新追加地址预约真实块，借用不跨调用。 */
    struct FamilyMergeRequest final
    {
        QueryResult Primary;
        QueryResult Secondary;
        Memory::BytePool &Pool;
    };

    /** @brief 合并去重只比较数值地址；保持出现顺序，不排序或重排上游事实。 */
    [[nodiscard]] inline auto ContainsAddress(const AddressList &Addresses,
                                              const boost::asio::ip::address &Address) noexcept -> bool
    {
        for (const auto &Entry : Addresses)
        {
            if (Entry == Address)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * @brief 合并 A 与 AAAA 结果，地址进入唯一 AnswerSet 事实。
     * @param Request 两族拥有型结果与真实池；池预算不足返回 ResourceUnavailable。
     * @return 合并后的查询结果；地址按出现顺序去重，错误取首个非成功者。
     * @details 双空（NXDOMAIN）保持 success+空；两族都无地址且有失败时，保留首个失败的
     *          领域类别与原生 cause。
     */
    [[nodiscard]] inline auto MergeFamilies(FamilyMergeRequest Request) -> QueryResult
    {
        QueryResult Merged;
        Merged.Response = std::move(Request.Primary.Response);
        Merged.ServerAddr = Request.Primary.ServerAddr;
        if (Merged.ServerAddr.empty())
        {
            Merged.ServerAddr = Request.Secondary.ServerAddr;
        }
        Merged.RttMs = std::max(Request.Primary.RttMs, Request.Secondary.RttMs);
        for (const auto &Address : Request.Secondary.Response.Ips)
        {
            if (ContainsAddress(Merged.Response.Ips, Address))
            {
                continue;
            }
            const auto Appended = Merged.Response.Ips.TryAppend(Address, Request.Pool);
            if (!Appended)
            {
                Merged.Error = Appended.error();
                return Merged;
            }
        }
        MergeTtl(Merged.Response, Request.Secondary.Response);
        if (Merged.Response.Ips.Empty() && Request.Primary.Error.Failed())
        {
            Merged.Error = Request.Primary.Error;
        }
        else if (Merged.Response.Ips.Empty() && Request.Secondary.Error.Failed())
        {
            Merged.Error = Request.Secondary.Error;
        }
        return Merged;
    }
}
