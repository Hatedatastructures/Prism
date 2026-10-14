/**
 * @file OperationsBootstrap.hpp
 * @brief Application 冷启动时生成唯一管理命令凭据和进程 incarnation。
 */
#pragma once

#include <Preview/Foundation/Utility/Crypto/Random.hpp>
#include <Preview/Operations/Models.hpp>

#include <openssl/crypto.h>

#include <expected>
#include <memory>
#include <utility>

namespace Preview::Application::OperationsBootstrap
{

    /** @brief 同步借用真实进程身份，只在 Operations 启动阶段调用一次。 */
    [[nodiscard]] inline auto CreateIdentity(
        const Preview::ProcessId Process)
        -> std::expected<std::shared_ptr<const Preview::Operations::BootstrapIdentity>,
                         Preview::Fault::Failure>
    {
        if (!Process)
        {
            return std::unexpected(
                Preview::Fault::Failure{Preview::Fault::Code::InvalidArgument});
        }
        Preview::Operations::BootstrapIdentity::Incarnation Incarnation{};
        Preview::Operations::BootstrapIdentity::CommandToken Token{};
        if (const auto Randomized = Preview::Crypto::FillRandom(Incarnation); !Randomized)
        {
            return std::unexpected(Randomized.error());
        }
        if (const auto Randomized = Preview::Crypto::FillRandom(Token); !Randomized)
        {
            OPENSSL_cleanse(Incarnation.data(), Incarnation.size());
            return std::unexpected(Randomized.error());
        }
        Preview::Operations::BootstrapIdentity::Options Options;
        Options.Process = Process;
        Options.ProcessIncarnation = std::move(Incarnation);
        Options.Token = std::move(Token);
        return std::make_shared<const Preview::Operations::BootstrapIdentity>(
            std::move(Options));
    }

} // namespace Preview::Application::OperationsBootstrap
