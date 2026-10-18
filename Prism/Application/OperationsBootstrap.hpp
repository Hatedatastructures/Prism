/**
 * @file OperationsBootstrap.hpp
 * @brief Application 冷启动时生成唯一管理命令凭据和进程 incarnation。
 */
#pragma once

#include <Prism/Foundation/Utility/Crypto/Random.hpp>
#include <Prism/Operations/Models.hpp>

#include <openssl/crypto.h>

#include <expected>
#include <memory>
#include <utility>

namespace Prism::Application::OperationsBootstrap
{

    /** @brief 同步借用真实进程身份，只在 Operations 启动阶段调用一次。 */
    [[nodiscard]] inline auto CreateIdentity(
        const Prism::ProcessId Process)
        -> std::expected<std::shared_ptr<const Prism::Operations::BootstrapIdentity>,
                         Prism::Fault::Failure>
    {
        if (!Process)
        {
            return std::unexpected(
                Prism::Fault::Failure{Prism::Fault::Code::InvalidArgument});
        }
        Prism::Operations::BootstrapIdentity::Incarnation Incarnation{};
        Prism::Operations::BootstrapIdentity::CommandToken Token{};
        if (const auto Randomized = Prism::Crypto::FillRandom(Incarnation); !Randomized)
        {
            return std::unexpected(Randomized.error());
        }
        if (const auto Randomized = Prism::Crypto::FillRandom(Token); !Randomized)
        {
            OPENSSL_cleanse(Incarnation.data(), Incarnation.size());
            return std::unexpected(Randomized.error());
        }
        Prism::Operations::BootstrapIdentity::Options Options;
        Options.Process = Process;
        Options.ProcessIncarnation = std::move(Incarnation);
        Options.Token = std::move(Token);
        return std::make_shared<const Prism::Operations::BootstrapIdentity>(
            std::move(Options));
    }

} // namespace Prism::Application::OperationsBootstrap
