/**
 * @file ServerKeyMaterial.hpp
 * @brief ECH 服务端 key 文件读取、清理与 BoringSSL key-container prepare。
 * @details 私钥只在本同步冷路径中借用，返回的 SSL_ECH_KEYS 独立拥有已复制 key。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Ech/Detail/Key.hpp>

#include <expected>
#include <filesystem>

namespace Prism::Ech::Detail
{
    /**
     * @brief 从原始私钥和单个序列化 ECHConfig 构造拥有型服务端 key container。
     * @param PrivateKeyPath 精确 32 字节 X25519 原始私钥文件。
     * @param EchConfigPath 单个 ECHConfig 文件；不接受 ECHConfigList。
     * @return 可安装的 owning key container；失败保留文件/配置错误。
     */
    [[nodiscard]] auto PrepareServerKeyFiles(
        const std::filesystem::path& PrivateKeyPath,
        const std::filesystem::path& EchConfigPath)
        -> std::expected<EchKeys, Prism::Fault::Failure>;
}
