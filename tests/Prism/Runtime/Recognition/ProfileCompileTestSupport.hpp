/**
 * @file ProfileCompileTestSupport.hpp
 * @brief ProfileCompileTest.cpp 拆分后的模块共享测试夹具与构造辅助。
 */
#pragma once

/**
 * @file ProfileCompileTest.cpp
 * @brief Profile 编译与启动配置校验测试
 */

#include <gtest/gtest.h>

#include <boost/asio/awaitable.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <Prism/Runtime/Recognition/Profile.hpp>

namespace
{

    namespace Net = boost::asio;
    namespace rec = Prism::Recognition;

    struct CandidateOptions
    {
        rec::CandidateId Id{rec::InvalidCandidate};
        std::string Name;
        Prism::Contract::ProtocolType Protocol{Prism::Contract::ProtocolType::Unknown};
        rec::CandidateKind Kind{rec::CandidateKind::Cleartext};
        std::uint16_t Priority{0};
        std::uint8_t Tier{0};
    };

    static_assert(std::is_aggregate_v<rec::CandidateSpec>);
    static_assert(!std::is_constructible_v<rec::CandidateSpec, rec::CandidateId, Prism::Contract::ProtocolType,
                                           rec::CandidateKind, std::uint16_t, rec::InspectFn, rec::PrepareFn,
                                           rec::CommitFn>);
    static_assert(!std::is_constructible_v<rec::CandidateSpec, rec::CandidateId, std::string, Prism::Contract::ProtocolType,
                                           rec::CandidateKind, std::uint16_t, rec::InspectFn, rec::PrepareFn,
                                           rec::CommitFn>);

    auto MakeCandidate(CandidateOptions Options) -> rec::CandidateSpec
    {
        rec::CandidateSpec Candidate;
        Candidate.Id = Options.Id;
        Candidate.Name = std::move(Options.Name);
        Candidate.Protocol = Options.Protocol;
        Candidate.Kind = Options.Kind;
        Candidate.Priority = Options.Priority;
        Candidate.Tier = Options.Tier;
        Candidate.MinimumBytes = 1;
        Candidate.Inspect = [](const rec::ProbeSnapshot &) -> rec::MatchState
        {
            return rec::MatchState::Structural;
        };
        Candidate.Commit = [](rec::CommitContext Context) -> Net::awaitable<rec::CommitResult>
        {
            rec::CommitResult Result;
            Result.Candidate = Context.Candidate;
            Result.Status = rec::RecognitionStatus::Accepted;
            Result.Transport = std::move(Context.Inbound);
            co_return Result;
        };
        if (Options.Kind == rec::CandidateKind::Opaque)
        {
            Candidate.Prepare = [](rec::PrepareContext Context) -> Net::awaitable<rec::PrepareResult>
            {
                rec::PrepareResult Result;
                Result.Candidate = Context.Candidate;
                Result.Status = rec::RecognitionStatus::Accepted;
                co_return Result;
            };
        }
        return Candidate;
    }

    auto MakeCandidate(rec::CandidateId Id, std::string Name, Prism::Contract::ProtocolType Protocol) -> rec::CandidateSpec
    {
        return MakeCandidate(CandidateOptions{Id, std::move(Name), Protocol});
    }

    auto MakeRoute(std::string Pattern, rec::CandidateId Candidate) -> rec::RouteBinding
    {
        rec::RouteBinding Route;
        Route.Pattern = std::move(Pattern);
        Route.Candidate = Candidate;
        return Route;
    }

    auto Compile(rec::ProfileSpec Spec)
    {
        return rec::Profile::Compile(std::move(Spec));
    }






































} // namespace


