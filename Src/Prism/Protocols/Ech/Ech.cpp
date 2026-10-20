/**
 * @file Ech.cpp
 * @brief ECH 密钥生成、文件 prepare 和 Native TLS context 安装实现。
 */
#include <Prism/Protocols/Ech/ServerKeys.hpp>
#include <Prism/Protocols/Ech/Detail/Hello.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <span>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace
{

    constexpr std::size_t MaxSerializedEchConfigBytes = 65535U;

    auto HpkeKeyFree(EVP_HPKE_KEY *Key) -> void
    {
        if (Key)
        {
            EVP_HPKE_KEY_free(Key);
        }
    }

    using HpkeKeyPtr = std::unique_ptr<EVP_HPKE_KEY, decltype(&HpkeKeyFree)>;

    auto MakeHpkeKey(
        const std::span<const std::uint8_t, Prism::Ech::Detail::PrivateKeyLen> PrivateKey)
        -> HpkeKeyPtr
    {
        auto *Key = EVP_HPKE_KEY_new();
        if (!Key)
        {
            return HpkeKeyPtr(nullptr, &HpkeKeyFree);
        }
        if (!EVP_HPKE_KEY_init(Key, EVP_hpke_x25519_hkdf_sha256(), PrivateKey.data(), PrivateKey.size()))
        {
            EVP_HPKE_KEY_free(Key);
            return HpkeKeyPtr(nullptr, &HpkeKeyFree);
        }
        return HpkeKeyPtr(Key, &HpkeKeyFree);
    }

    auto BuildConfigList(const std::span<const std::uint8_t> EchConfig)
        -> std::vector<std::uint8_t>
    {
        if (EchConfig.size() > 0xFFFF)
        {
            return {};
        }
        std::vector<std::uint8_t> List;
        List.reserve(2 + EchConfig.size());
        List.push_back(static_cast<std::uint8_t>(EchConfig.size() >> 8));
        List.push_back(static_cast<std::uint8_t>(EchConfig.size() & 0xFF));
        List.insert(List.end(), EchConfig.begin(), EchConfig.end());
        return List;
    }

    [[nodiscard]] auto ReadFileSize(
        const std::filesystem::path &Path,
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

    struct SensitivePrivateKey final
    {
        std::array<std::uint8_t, Prism::Ech::Detail::PrivateKeyLen> Bytes{};

        ~SensitivePrivateKey()
        {
            OPENSSL_cleanse(Bytes.data(), Bytes.size());
        }
    };

    [[nodiscard]] auto ReadPrivateKey(
        const std::filesystem::path &Path,
        SensitivePrivateKey &Output)
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
        File.read(reinterpret_cast<char *>(Output.Bytes.data()),
                  static_cast<std::streamsize>(Output.Bytes.size()));
        if (File.gcount() != static_cast<std::streamsize>(Output.Bytes.size()) ||
            File.peek() != std::char_traits<char>::eof())
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        return {};
    }

    [[nodiscard]] auto ReadSerializedEchConfig(const std::filesystem::path &Path)
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
        File.read(reinterpret_cast<char *>(Config.data()),
                  static_cast<std::streamsize>(Config.size()));
        if (File.gcount() != static_cast<std::streamsize>(Config.size()) ||
            File.peek() != std::char_traits<char>::eof())
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::ConfigErr});
        }
        return Config;
    }

} // namespace

namespace Prism::Ech::Detail
{

    auto GenerateKeypair(
        const std::string_view PublicName,
        const std::size_t MaxNameLen,
        EchKeypair &Output) -> Prism::Fault::Code
    {
        auto *RawKey = EVP_HPKE_KEY_new();
        if (!RawKey)
        {
            return Prism::Fault::Code::CryptoError;
        }
        if (!EVP_HPKE_KEY_generate(RawKey, EVP_hpke_x25519_hkdf_sha256()))
        {
            EVP_HPKE_KEY_free(RawKey);
            return Prism::Fault::Code::CryptoError;
        }
        HpkeKeyPtr Key(RawKey, &HpkeKeyFree);

        std::array<std::uint8_t, PrivateKeyLen> PrivateKey{};
        std::size_t PrivateLen = 0;
        if (!EVP_HPKE_KEY_private_key(Key.get(), PrivateKey.data(), &PrivateLen, PrivateKey.size()))
        {
            return Prism::Fault::Code::CryptoError;
        }

        std::uint8_t ConfigId = 0;
        if (RAND_bytes(&ConfigId, 1) != 1)
        {
            return Prism::Fault::Code::CryptoError;
        }
        std::uint8_t *ConfigOut = nullptr;
        std::size_t ConfigLen = 0;
        if (!SSL_marshal_ech_config(&ConfigOut, &ConfigLen, ConfigId, Key.get(),
                                    std::string(PublicName).c_str(), MaxNameLen))
        {
            return Prism::Fault::Code::CryptoError;
        }

        std::copy(PrivateKey.begin(), PrivateKey.end(), Output.PrivateKey.begin());
        Output.EchConfig.assign(ConfigOut, ConfigOut + ConfigLen);
        OPENSSL_free(ConfigOut);
        Output.EchConfigList = BuildConfigList(Output.EchConfig);
        if (Output.EchConfigList.empty())
        {
            Output.EchConfig.clear();
            return Prism::Fault::Code::InvalidArgument;
        }
        return Prism::Fault::Code::Success;
    }

    auto KeypairFromPrivate(const KeypairParameters &Params) -> Prism::Fault::Code
    {
        auto Key = MakeHpkeKey(Params.PrivateKey);
        if (!Key)
        {
            return Prism::Fault::Code::CryptoError;
        }

        std::uint8_t *ConfigOut = nullptr;
        std::size_t ConfigLen = 0;
        if (!SSL_marshal_ech_config(&ConfigOut, &ConfigLen, 0, Key.get(),
                                    std::string(Params.PublicName).c_str(), Params.MaxNameLen))
        {
            return Prism::Fault::Code::CryptoError;
        }

        std::copy(Params.PrivateKey.begin(), Params.PrivateKey.end(), Params.Out.PrivateKey.begin());
        Params.Out.EchConfig.assign(ConfigOut, ConfigOut + ConfigLen);
        OPENSSL_free(ConfigOut);
        Params.Out.EchConfigList = BuildConfigList(Params.Out.EchConfig);
        if (Params.Out.EchConfigList.empty())
        {
            Params.Out.EchConfig.clear();
            return Prism::Fault::Code::InvalidArgument;
        }
        return Prism::Fault::Code::Success;
    }

    auto MakeEchKeys(
        const std::span<const std::uint8_t, PrivateKeyLen> PrivateKey,
        const std::span<const std::uint8_t> EchConfig) -> EchKeys
    {
        auto Key = MakeHpkeKey(PrivateKey);
        if (!Key)
        {
            return EchKeys(nullptr, &SSL_ECH_KEYS_free);
        }
        EchKeys Keys(SSL_ECH_KEYS_new(), &SSL_ECH_KEYS_free);
        if (!Keys)
        {
            return Keys;
        }
        if (!SSL_ECH_KEYS_add(Keys.get(), 1, EchConfig.data(), EchConfig.size(), Key.get()))
        {
            return EchKeys(nullptr, &SSL_ECH_KEYS_free);
        }
        return Keys;
    }

    auto PrepareServerKeyFiles(
        const std::filesystem::path &PrivateKeyPath,
        const std::filesystem::path &EchConfigPath)
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

    auto ContainsEchExtension(const std::span<const std::byte> Raw) -> bool
    {
        // TLS 记录头：5 字节
        if (Raw.size() < 5 || std::to_integer<std::uint8_t>(Raw[0]) != 0x16)
        {
            return false;
        }
        const auto RecordLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[3])) << 8) |
                               static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[4]));
        if (RecordLen < 4 || RecordLen > Raw.size() - 5)
        {
            return false;
        }
        std::size_t Off = 5;
        // handshake_type + handshake_len(3)
        if (Off > 5 + RecordLen || 5 + RecordLen - Off < 4 ||
            std::to_integer<std::uint8_t>(Raw[Off]) != 0x01)
        {
            return false;
        }
        const auto HsLen = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Raw[Off + 1])) << 16) |
                           (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Raw[Off + 2])) << 8) |
                           static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(Raw[Off + 3]));
        Off += 4;
        if (HsLen > 5 + RecordLen - Off)
        {
            return false;
        }
        const auto HandshakeEnd = Off + HsLen;
        // LegacyVersion(2) + random(32)
        if (Off > HandshakeEnd || HandshakeEnd - Off < 34)
        {
            return false;
        }
        Off += 34;
        // SessionId
        if (Off >= HandshakeEnd)
        {
            return false;
        }
        const auto SidLen = std::to_integer<std::uint8_t>(Raw[Off]);
        ++Off;
        if (SidLen > HandshakeEnd - Off)
        {
            return false;
        }
        Off += SidLen;
        // cipher_suites
        if (Off > HandshakeEnd || HandshakeEnd - Off < 2)
        {
            return false;
        }
        const auto CsLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off])) << 8) |
                           static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 1]));
        if (CsLen > HandshakeEnd - Off - 2)
        {
            return false;
        }
        Off += 2 + CsLen;
        // compression_methods
        if (Off >= HandshakeEnd)
        {
            return false;
        }
        const auto CompLen = std::to_integer<std::uint8_t>(Raw[Off]);
        ++Off;
        if (CompLen > HandshakeEnd - Off)
        {
            return false;
        }
        Off += CompLen;
        // extensions
        if (Off > HandshakeEnd || HandshakeEnd - Off < 2)
        {
            return false;
        }
        const auto ExtLen = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off])) << 8) |
                            static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 1]));
        Off += 2;
        if (Off > HandshakeEnd || ExtLen > HandshakeEnd - Off)
        {
            return false;
        }
        // 扫描扩展项
        const std::size_t End = Off + ExtLen;
        while (End - Off >= 4)
        {
            const auto Type = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 1]));
            const auto Len = (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 2])) << 8) |
                             static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(Raw[Off + 3]));
            if (Len > End - Off - 4)
            {
                return false;
            }
            if (Type == EchExtensionType)
            {
                return true;
            }
            Off += 4 + Len;
        }
        return false;
    }

} // namespace Prism::Ech::Detail

namespace Prism::Ech
{
    PreparedServerKeys::PreparedServerKeys(Detail::EchKeys Keys)
        : Keys_(std::move(Keys))
    {
    }

    auto PrepareServerKeys(const ServerKeyFiles Files)
        -> std::expected<PreparedServerKeys, Prism::Fault::Failure>
    {
        if (Files.PrivateKey.empty() || Files.EchConfig.empty())
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        auto Keys = Detail::PrepareServerKeyFiles(Files.PrivateKey, Files.EchConfig);
        if (!Keys)
        {
            return std::unexpected(Keys.error());
        }
        return PreparedServerKeys(std::move(*Keys));
    }

    auto InstallServerKeys(SSL_CTX *Context, PreparedServerKeys Prepared)
        -> std::expected<void, Prism::Fault::Failure>
    {
        if (!Context || !Prepared.Keys_)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::InvalidArgument});
        }
        if (SSL_CTX_set1_ech_keys(Context, Prepared.Keys_.get()) != 1)
        {
            return std::unexpected(Prism::Fault::Failure{
                Prism::Fault::Code::CryptoError});
        }
        return {};
    }

} // namespace Prism::Ech
