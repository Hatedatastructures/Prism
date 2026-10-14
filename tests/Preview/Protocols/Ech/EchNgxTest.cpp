/**
 * @file EchNgxTest.cpp
 * @brief ECH 密钥生成与检测测试（T2-3）
 * @details 覆盖：
 *          - GenerateKeypair：随机密钥 + ECHConfig 序列化
 *          - KeypairFromPrivate：私钥恢复 ECHConfig（确定性）
 *          - MakeEchKeys：SSL_ECH_KEYS 构造
 *          - ContainsEchExtension：ClientHello 扫描（含/不含）
 */

#include <Preview/Protocols/Ech/Detail/Hello.hpp>
#include <Preview/Protocols/Ech/Detail/Key.hpp>
#include <Preview/Protocols/Ech/ServerKeys.hpp>

#include <TestSupport/Tls/MockTlsServer.hpp>

#include <openssl/bio.h>
#include <openssl/curve25519.h>
#include <openssl/ssl.h>

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>


namespace
{
    namespace Ech = Preview::Ech;

    struct TemporaryEchFiles final
    {
        explicit TemporaryEchFiles(const std::string_view Label)
        {
            const auto Unique = std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count());
            Directory = std::filesystem::temp_directory_path() /
                ("Prism-Ech-" + std::string(Label) + "-" + Unique);
            PrivateKey = Directory / "server.key";
            EchConfig = Directory / "server.ech";
            std::error_code Error;
            Created = std::filesystem::create_directory(Directory, Error) && !Error;
        }

        ~TemporaryEchFiles()
        {
            std::error_code Error;
            if (Created)
            {
                std::filesystem::remove_all(Directory, Error);
            }
        }

        [[nodiscard]] auto Write(const Ech::Detail::EchKeypair& Keypair) const -> bool
        {
            std::ofstream Key(PrivateKey, std::ios::binary);
            std::ofstream Config(EchConfig, std::ios::binary);
            if (!Key || !Config)
            {
                return false;
            }
            Key.write(reinterpret_cast<const char*>(Keypair.PrivateKey.data()),
                      static_cast<std::streamsize>(Keypair.PrivateKey.size()));
            Config.write(reinterpret_cast<const char*>(Keypair.EchConfig.data()),
                         static_cast<std::streamsize>(Keypair.EchConfig.size()));
            return Key.good() && Config.good();
        }

        [[nodiscard]] auto Files() const -> Ech::ServerKeyFiles
        {
            return {PrivateKey, EchConfig};
        }

        std::filesystem::path Directory;
        std::filesystem::path PrivateKey;
        std::filesystem::path EchConfig;
        bool Created{false};
    };

    struct SslContextDeleter final
    {
        auto operator()(SSL_CTX* Context) const noexcept -> void
        {
            SSL_CTX_free(Context);
        }
    };

    struct SslDeleter final
    {
        auto operator()(SSL* Connection) const noexcept -> void
        {
            SSL_free(Connection);
        }
    };

    struct BioDeleter final
    {
        auto operator()(BIO* Value) const noexcept -> void
        {
            BIO_free(Value);
        }
    };

    using SslContextPtr = std::unique_ptr<SSL_CTX, SslContextDeleter>;
    using SslPtr = std::unique_ptr<SSL, SslDeleter>;
    using BioPtr = std::unique_ptr<BIO, BioDeleter>;

    struct HandshakeObservation final
    {
        bool ClientComplete{false};
        bool ServerComplete{false};
        bool EchAccepted{false};
        std::string ServerName;
    };

    /** @brief 单次测试 ClientHello 的 server_name、ECHConfigList 和 GREASE 选择。 */
    struct EchClientHelloOptions final
    {
        std::span<const std::uint8_t> EchConfigList;
        std::string_view ServerName;
        bool SendGrease{false};
    };

    [[nodiscard]] auto ProgressHandshake(SSL* Connection, bool& Complete) -> bool
    {
        const auto Result = SSL_do_handshake(Connection);
        if (Result == 1)
        {
            Complete = true;
            return true;
        }
        const auto Error = SSL_get_error(Connection, Result);
        return Error == SSL_ERROR_WANT_READ || Error == SSL_ERROR_WANT_WRITE;
    }

    [[nodiscard]] auto RunEchHandshake(
        SSL_CTX* ServerContext,
        const EchClientHelloOptions& Options) -> std::optional<HandshakeObservation>
    {
        SslContextPtr ClientContext(SSL_CTX_new(TLS_method()));
        if (!ClientContext || SSL_CTX_set_min_proto_version(ClientContext.get(), TLS1_3_VERSION) != 1 ||
            SSL_CTX_set_max_proto_version(ClientContext.get(), TLS1_3_VERSION) != 1)
        {
            return std::nullopt;
        }
        SslPtr Client(SSL_new(ClientContext.get()));
        SslPtr Server(SSL_new(ServerContext));
        if (!Client || !Server ||
            SSL_set_tlsext_host_name(Client.get(), std::string(Options.ServerName).c_str()) != 1)
        {
            return std::nullopt;
        }
        if (Options.SendGrease)
        {
            SSL_set_enable_ech_grease(Client.get(), 1);
        }
        else if (Options.EchConfigList.empty() ||
                 SSL_set1_ech_config_list(Client.get(), Options.EchConfigList.data(),
                                          Options.EchConfigList.size()) != 1)
        {
            return std::nullopt;
        }

        BIO* ClientRaw = nullptr;
        BIO* ServerRaw = nullptr;
        if (BIO_new_bio_pair(&ClientRaw, 4096, &ServerRaw, 4096) != 1)
        {
            if (ClientRaw)
            {
                BIO_free(ClientRaw);
            }
            if (ServerRaw)
            {
                BIO_free(ServerRaw);
            }
            return std::nullopt;
        }
        BioPtr ClientBio(ClientRaw);
        BioPtr ServerBio(ServerRaw);
        SSL_set_bio(Client.get(), ClientBio.release(), ClientRaw);
        SSL_set_bio(Server.get(), ServerBio.release(), ServerRaw);
        SSL_set_connect_state(Client.get());
        SSL_set_accept_state(Server.get());

        HandshakeObservation Result;
        for (std::size_t Attempt = 0; Attempt < 128; ++Attempt)
        {
            if (!Result.ClientComplete && !ProgressHandshake(Client.get(), Result.ClientComplete))
            {
                return std::nullopt;
            }
            if (!Result.ServerComplete && !ProgressHandshake(Server.get(), Result.ServerComplete))
            {
                return std::nullopt;
            }
            if (Result.ClientComplete && Result.ServerComplete)
            {
                break;
            }
        }
        if (!Result.ClientComplete || !Result.ServerComplete)
        {
            return std::nullopt;
        }
        Result.EchAccepted = SSL_ech_accepted(Server.get()) == 1;
        if (const auto* Name = SSL_get_servername(Server.get(), TLSEXT_NAMETYPE_host_name))
        {
            Result.ServerName = Name;
        }
        return Result;
    }

    /// 构造最小 ClientHello（无扩展）
    auto MakeClientHello() -> std::vector<std::byte>
    {
        std::vector<std::byte> ClientHello;
        // 记录头
        ClientHello.push_back(std::byte{0x16});
        ClientHello.push_back(std::byte{0x03});
        ClientHello.push_back(std::byte{0x01});
        // 长度占位
        ClientHello.push_back(std::byte{0x00});
        ClientHello.push_back(std::byte{0x00});
        // ClientHello 体
        ClientHello.push_back(std::byte{0x01});
        ClientHello.push_back(std::byte{0x00});
        ClientHello.push_back(std::byte{0x00});
        ClientHello.push_back(std::byte{0x00});
        // LegacyVersion
        ClientHello.push_back(std::byte{0x03});
        ClientHello.push_back(std::byte{0x03});
        // random 32
        for (int Index = 0; Index < 32; ++Index)
        {
            ClientHello.push_back(std::byte{0xAA});
        }
        // SessionId
        ClientHello.push_back(std::byte{0x00});
        // cipher_suites
        ClientHello.push_back(std::byte{0x00});
        ClientHello.push_back(std::byte{0x02});
        ClientHello.push_back(std::byte{0x13});
        ClientHello.push_back(std::byte{0x01});
        // compression
        ClientHello.push_back(std::byte{0x01});
        ClientHello.push_back(std::byte{0x00});
        return ClientHello;
    }

    /// 追加扩展项
    void AddExtension(std::vector<std::byte> &ClientHello, std::uint16_t Type, std::span<const std::byte> Data)
    {
        // 定位 extensions 长度位置：固定在末尾（无扩展时）
        // 先加 extensions 头（2 字节长度），再追加项
        const auto ExtensionStart = ClientHello.size();
        ClientHello.push_back(std::byte{0x00});
        ClientHello.push_back(std::byte{0x00});
        // 追加项
        ClientHello.push_back(static_cast<std::byte>((Type >> 8) & 0xFF));
        ClientHello.push_back(static_cast<std::byte>(Type & 0xFF));
        ClientHello.push_back(static_cast<std::byte>((Data.size() >> 8) & 0xFF));
        ClientHello.push_back(static_cast<std::byte>(Data.size() & 0xFF));
        ClientHello.insert(ClientHello.end(), Data.begin(), Data.end());
        // 更新长度
        const auto Total = ClientHello.size() - (ExtensionStart + 2);
        ClientHello[ExtensionStart] = static_cast<std::byte>((Total >> 8) & 0xFF);
        ClientHello[ExtensionStart + 1] = static_cast<std::byte>(Total & 0xFF);
        // 更新记录长度
        const auto RecordLength = ClientHello.size() - 5;
        ClientHello[3] = static_cast<std::byte>((RecordLength >> 8) & 0xFF);
        ClientHello[4] = static_cast<std::byte>(RecordLength & 0xFF);
        // 更新 ClientHello handshake 长度（记录头之后的 handshake body）。
        const auto HandshakeLength = ClientHello.size() - 9;
        ClientHello[6] = static_cast<std::byte>((HandshakeLength >> 16) & 0xFF);
        ClientHello[7] = static_cast<std::byte>((HandshakeLength >> 8) & 0xFF);
        ClientHello[8] = static_cast<std::byte>(HandshakeLength & 0xFF);
    }
} // namespace

TEST(EchNgxKeygen, GenerateKeypair)
{
    Ech::Detail::EchKeypair Keypair;
    const auto Code = Ech::Detail::GenerateKeypair("example.com", 32, Keypair);
    EXPECT_EQ(Code, Preview::Fault::Code::Success);
    EXPECT_FALSE(Keypair.EchConfig.empty());
    EXPECT_FALSE(Keypair.EchConfigList.empty());
    // ECHConfigList = 2 字节长度前缀 + Config
    EXPECT_EQ(Keypair.EchConfigList.size(), Keypair.EchConfig.size() + 2);
    EXPECT_EQ(Keypair.EchConfigList[0], static_cast<std::uint8_t>(Keypair.EchConfig.size() >> 8));
    EXPECT_EQ(Keypair.EchConfigList[1], static_cast<std::uint8_t>(Keypair.EchConfig.size() & 0xFF));
}

TEST(EchNgxKeygen, KeypairFromPrivateDeterministic)
{
    std::array<std::uint8_t, Ech::Detail::PrivateKeyLen> PrivateKey{};
    for (std::size_t Index = 0; Index < PrivateKey.size(); ++Index)
    {
        PrivateKey[Index] = static_cast<std::uint8_t>(Index + 1);
    }

    Ech::Detail::EchKeypair FirstKeypair;
    Ech::Detail::EchKeypair SecondKeypair;
    EXPECT_EQ(Ech::Detail::KeypairFromPrivate({PrivateKey, "example.com", 32, FirstKeypair}),
              Preview::Fault::Code::Success);
    EXPECT_EQ(Ech::Detail::KeypairFromPrivate({PrivateKey, "example.com", 32, SecondKeypair}),
              Preview::Fault::Code::Success);

    // 确定性：相同私钥 → 相同 ECHConfig
    ASSERT_EQ(FirstKeypair.EchConfig.size(), SecondKeypair.EchConfig.size());
    EXPECT_EQ(std::memcmp(FirstKeypair.EchConfig.data(), SecondKeypair.EchConfig.data(), FirstKeypair.EchConfig.size()), 0);
}

TEST(EchNgxKeygen, MakeEchKeys)
{
    Ech::Detail::EchKeypair Keypair;
    ASSERT_EQ(Ech::Detail::GenerateKeypair("example.com", 32, Keypair), Preview::Fault::Code::Success);

    auto Keys = Ech::Detail::MakeEchKeys(Keypair.PrivateKey, Keypair.EchConfig);
    ASSERT_NE(Keys, nullptr);
}

TEST(EchNgxKeygen, ClientHelloNoEch)
{
    auto ClientHello = MakeClientHello();
    EXPECT_FALSE(Ech::Detail::ContainsEchExtension(ClientHello));
}

TEST(EchNgxKeygen, ClientHelloWithEch)
{
    auto ClientHello = MakeClientHello();
    std::array<std::byte, 4> EchExtension{std::byte{0x00}, std::byte{0x20}, std::byte{0x01}, std::byte{0x02}};
    AddExtension(ClientHello, Ech::Detail::EchExtensionType, EchExtension);
    EXPECT_TRUE(Ech::Detail::ContainsEchExtension(ClientHello));
}

TEST(EchNgxKeygen, ClientHelloWithTruncatedEchExtensionIsRejected)
{
    auto ClientHello = MakeClientHello();
    std::array<std::byte, 2> EchExtension{std::byte{0x01}, std::byte{0x02}};
    AddExtension(ClientHello, Ech::Detail::EchExtensionType, EchExtension);
    ASSERT_GE(ClientHello.size(), std::size_t{4});
    ClientHello[ClientHello.size() - 4] = std::byte{0xff};
    ClientHello[ClientHello.size() - 3] = std::byte{0xff};
    EXPECT_FALSE(Ech::Detail::ContainsEchExtension(ClientHello));
}

TEST(EchNgxKeygen, ClientHelloOtherExtension)
{
    auto ClientHello = MakeClientHello();
    std::array<std::byte, 2> ServerNameExtension{std::byte{0x00}, std::byte{0x00}};
    AddExtension(ClientHello, 0x0000, ServerNameExtension); // server_name
    EXPECT_FALSE(Ech::Detail::ContainsEchExtension(ClientHello));
}

TEST(EchNgxKeygen, PreparedServerKeysBindAndDecryptInnerClientHello)
{
    auto Identity = Preview::Testing::Tls::TlsServerIdentity::Create();
    ASSERT_NE(Identity, nullptr);
    Ech::Detail::EchKeypair Keypair;
    ASSERT_EQ(Ech::Detail::GenerateKeypair("public.example", 32, Keypair),
              Preview::Fault::Code::Success);
    TemporaryEchFiles Files("accepted");
    ASSERT_TRUE(Files.Created);
    ASSERT_TRUE(Files.Write(Keypair));

    auto Prepared = Ech::PrepareServerKeys(Files.Files());
    ASSERT_TRUE(Prepared);
    ASSERT_TRUE(Ech::InstallServerKeys(Identity->Context(), std::move(*Prepared)));

    const auto Handshake = RunEchHandshake(
        Identity->Context(), EchClientHelloOptions{Keypair.EchConfigList, "secret.example", false});
    ASSERT_TRUE(Handshake.has_value());
    EXPECT_TRUE(Handshake->EchAccepted);
    EXPECT_EQ(Handshake->ServerName, "secret.example");
}

TEST(EchNgxKeygen, PreparedServerKeysRejectMismatchedPrivateKey)
{
    Ech::Detail::EchKeypair Keypair;
    ASSERT_EQ(Ech::Detail::GenerateKeypair("public.example", 32, Keypair),
              Preview::Fault::Code::Success);
    std::array<std::uint8_t, 32> OriginalPublicKey{};
    X25519_public_from_private(OriginalPublicKey.data(), Keypair.PrivateKey.data());
    // X25519 会清除首字节的最低三位，修改第二字节才形成真实不匹配的密钥。
    Keypair.PrivateKey[1] ^= 0x01U;
    std::array<std::uint8_t, 32> ChangedPublicKey{};
    X25519_public_from_private(ChangedPublicKey.data(), Keypair.PrivateKey.data());
    ASSERT_NE(ChangedPublicKey, OriginalPublicKey);
    TemporaryEchFiles Files("mismatch");
    ASSERT_TRUE(Files.Created);
    ASSERT_TRUE(Files.Write(Keypair));

    const auto Prepared = Ech::PrepareServerKeys(Files.Files());
    ASSERT_FALSE(Prepared);
    EXPECT_EQ(Prepared.error().Code, Preview::Fault::Code::ConfigErr);
}

TEST(EchNgxKeygen, NativeTlsAcceptsGreaseWithoutTreatingItAsNegotiatedEch)
{
    auto Identity = Preview::Testing::Tls::TlsServerIdentity::Create();
    ASSERT_NE(Identity, nullptr);

    const auto Handshake = RunEchHandshake(
        Identity->Context(), EchClientHelloOptions{{}, "public.example", true});
    ASSERT_TRUE(Handshake.has_value());
    EXPECT_FALSE(Handshake->EchAccepted);
    EXPECT_EQ(Handshake->ServerName, "public.example");
}
