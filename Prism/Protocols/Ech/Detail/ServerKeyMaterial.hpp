/**
 * @file ServerKeyMaterial.hpp
 * @brief ECH 服务端 key 文件读取、清理与 BoringSSL key-container prepare。
 * @details 私钥只在本同步冷路径中借用，返回的 SSL_ECH_KEYS 独立拥有已复制 key。
 */
#pragma once

#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Protocols/Ech/Detail/Key.hpp>

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <fstream>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Ech::Detail
{
    inline constexpr std::size_t MaxSerializedEchConfigBytes = 65535U;

    /** @brief 同步借用并在离开作用域时清除原始 ECH 私钥。 */
    struct SensitivePrivateKey final
    {
        std::array<std::uint8_t, PrivateKeyLen> Bytes{};

        ~SensitivePrivateKey()
        {
            OPENSSL_cleanse(Bytes.data(), Bytes.size());
        }
    };

    [[nodiscard]] inline auto ReadFileSize(
        const std::filesystem::path& Path,
        const std::uintmax_t Maximum)
        -> std::expected<std::uintmax_t, Prism::Fault::Failure>
    {
        std::error_code Error;
        const auto Size = std::filesystem::file_size(Path, Error);
        if (Error)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::FileOpenfail, Error});
        }
        if (Size == 0 || Size > Maximum)
        {
            auto Code = Prism::Fault::Code::InvalidArgument;
            if (Size > Maximum)
            {
                Code = Prism::Fault::Code::OversizedMsg;
            }
            return std::unexpected(Prism::Fault::Failure{Code});
        }
        return Size;
    }

    [[nodiscard]] inline auto ReadPrivateKey(
        const std::filesystem::path& Path,
        SensitivePrivateKey& Output)
        -> std::expected<void, Prism::Fault::Failure>
    {
        const auto Size = ReadFileSize(Path, Output.Bytes.size());
        if (!Size)
        {
            return std::unexpected(Size.error());
        }
        if (*Size != Output.Bytes.size())
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        std::ifstream File(Path, std::ios::binary);
        if (!File)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::FileOpenfail});
        }
        File.read(reinterpret_cast<char*>(Output.Bytes.data()),
                  static_cast<std::streamsize>(Output.Bytes.size()));
        if (File.gcount() != static_cast<std::streamsize>(Output.Bytes.size()) ||
            File.peek() != std::char_traits<char>::eof())
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        return {};
    }

    [[nodiscard]] inline auto ReadSerializedEchConfig(
        const std::filesystem::path& Path)
        -> std::expected<std::vector<std::uint8_t>, Prism::Fault::Failure>
    {
        const auto Size = ReadFileSize(Path, MaxSerializedEchConfigBytes);
        if (!Size)
        {
            return std::unexpected(Size.error());
        }
        std::vector<std::uint8_t> Config(static_cast<std::size_t>(*Size));
        std::ifstream File(Path, std::ios::binary);
        if (!File)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::FileOpenfail});
        }
        File.read(reinterpret_cast<char*>(Config.data()),
                  static_cast<std::streamsize>(Config.size()));
        if (File.gcount() != static_cast<std::streamsize>(Config.size()) ||
            File.peek() != std::char_traits<char>::eof())
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ConfigErr});
        }
        return Config;
    }

    /**
     * @brief 从原始私钥和单个序列化 ECHConfig 构造拥有型服务端 key container。
     * @param PrivateKeyPath 精确 32 字节 X25519 原始私钥文件。
     * @param EchConfigPath 单个 ECHConfig 文件；不接受 ECHConfigList。
     * @return 可安装的 owning key container；失败保留文件/配置错误。
     */
    [[nodiscard]] inline auto PrepareServerKeyFiles(
        const std::filesystem::path& PrivateKeyPath,
        const std::filesystem::path& EchConfigPath)
        -> std::expected<EchKeys, Prism::Fault::Failure>
    {
        SensitivePrivateKey PrivateKey;
        if (const auto Read = ReadPrivateKey(PrivateKeyPath, PrivateKey); !Read)
        {
            return std::unexpected(Read.error());
        }
        auto Config = ReadSerializedEchConfig(EchConfigPath);
        if (!Config)
        {
            return std::unexpected(Config.error());
        }
        auto Keys = MakeEchKeys(PrivateKey.Bytes, *Config);
        if (!Keys)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ConfigErr});
        }
        return std::move(Keys);
    }
}
