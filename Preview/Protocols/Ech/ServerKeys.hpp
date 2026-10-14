/**
 * @file ServerKeys.hpp
 * @brief ECH 服务端 key prepare 与 Native SSL_CTX bind 公共入口。
 * @details 文件路径在冷启动按值移交；私钥只在 prepare 帧内存在并在销毁时清零。
 *          PreparedServerKeys 是一次性 move-only owner；成功绑定后 SSL_CTX 持有
 *          BoringSSL ref-counted SSL_ECH_KEYS，直到 context 最终销毁。
 */
#pragma once

#include <Preview/Foundation/Fault/Failure.hpp>
#include <Preview/Protocols/Ech/Detail/Key.hpp>
#include <Preview/Protocols/Ech/Detail/ServerKeyMaterial.hpp>

#include <openssl/ssl.h>

#include <expected>
#include <filesystem>
#include <memory>
#include <utility>

namespace Preview::Ech
{
    /** @brief ECH 单个服务端 key 的原始文件位置。 */
    struct ServerKeyFiles final
    {
        std::filesystem::path PrivateKey;
        std::filesystem::path EchConfig;
    };

    /**
     * @brief 已校验但尚未绑定 SSL_CTX 的 move-only ECH key owner。
     * @details 仅为冷路径一次性过渡值；析构释放尚未绑定的 BoringSSL keys。
     */
    class PreparedServerKeys final
    {
    public:
        PreparedServerKeys(PreparedServerKeys&&) noexcept = default;
        auto operator=(PreparedServerKeys&&) noexcept -> PreparedServerKeys& = default;
        PreparedServerKeys(const PreparedServerKeys&) = delete;
        auto operator=(const PreparedServerKeys&) -> PreparedServerKeys& = delete;
        ~PreparedServerKeys() = default;

    private:
        friend auto PrepareServerKeys(ServerKeyFiles Files)
            -> std::expected<PreparedServerKeys, Preview::Fault::Failure>;
        friend auto InstallServerKeys(SSL_CTX* Context, PreparedServerKeys Prepared)
            -> std::expected<void, Preview::Fault::Failure>;

        explicit PreparedServerKeys(Detail::EchKeys Keys) : Keys_(std::move(Keys))
        {
        }

        Detail::EchKeys Keys_{nullptr, &SSL_ECH_KEYS_free};
    };

    /**
     * @brief 冷读 raw X25519 key 与单个序列化 ECHConfig 并验证二者匹配。
     * @param Files 私钥和单个 ECHConfig 文件路径；Config 不是外层 ECHConfigList。
     * @return 一次性 prepared keys；文件、长度、格式或公私钥不匹配时返回 typed Fault。
     * @note 读取上限分别为 32 字节私钥和 65535 字节 ECHConfig；不会记录文件内容。
     */
    [[nodiscard]] inline auto PrepareServerKeys(ServerKeyFiles Files)
        -> std::expected<PreparedServerKeys, Preview::Fault::Failure>
    {
        if (Files.PrivateKey.empty() || Files.EchConfig.empty())
        {
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        auto Keys = Detail::PrepareServerKeyFiles(Files.PrivateKey, Files.EchConfig);
        if (!Keys)
        {
            return std::unexpected(Keys.error());
        }
        return PreparedServerKeys(std::move(*Keys));
    }

    /**
     * @brief 将 prepared keys 一次性绑定到 Native TLS context。
     * @param Context 活至所有服务端 TLS 连接和握手退出的 SSL_CTX。
     * @param Prepared 移交的 prepared owner；成功后 SSL_CTX 通过 BoringSSL set1 增加引用。
     * @return 安装结果；失败后 prepared owner 释放密钥，不留下半绑定状态。
     * @note prepare 将唯一 ECHConfig 注册为 retry config，满足 BoringSSL 安装前提。
     */
    [[nodiscard]] inline auto InstallServerKeys(SSL_CTX* Context, PreparedServerKeys Prepared)
        -> std::expected<void, Preview::Fault::Failure>
    {
        if (!Context || !Prepared.Keys_)
        {
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::InvalidArgument});
        }
        if (SSL_CTX_set1_ech_keys(Context, Prepared.Keys_.get()) != 1)
        {
            return std::unexpected(Preview::Fault::Failure{
                Preview::Fault::Code::CryptoError});
        }
        return {};
    }
}
