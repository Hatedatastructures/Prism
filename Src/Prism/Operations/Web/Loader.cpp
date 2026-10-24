/** @file Loader.cpp @brief 后台资源清单验证与资源读取实现。 */
#include <Prism/Operations/Web/Loader.hpp>
#include <Prism/Foundation/Fault/Failure.hpp>
#include <Prism/Operations/Web/Catalog.hpp>

#include <glaze/glaze.hpp>
#include <openssl/sha.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <expected>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace Prism::Operations::Web
{
    namespace Detail
    {
        inline constexpr auto StrictOptions = []
        {
            glz::opts Result;
            Result.error_on_unknown_keys = true;
            Result.error_on_missing_keys = true;
            return Result;
        }();

        [[nodiscard]] auto ReadFile(const std::filesystem::path& Path, std::size_t Limit)
            -> std::expected<std::string, Prism::Fault::Failure>
        {
            std::error_code Error;
            const auto Size = std::filesystem::file_size(Path, Error);
            if (Error)
                return std::unexpected(Prism::Fault::FromNative(Error));
            if (Size > Limit)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            std::ifstream Input(Path, std::ios::binary);
            if (!Input)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::IoError});
            std::string Bytes(static_cast<std::size_t>(Size), '\0');
            Input.read(Bytes.data(), static_cast<std::streamsize>(Bytes.size()));
            if (Input.gcount() != static_cast<std::streamsize>(Bytes.size()) || Input.peek() != EOF)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            return Bytes;
        }

        [[nodiscard]] auto Digest(std::string_view Bytes) -> std::string
        {
            std::array<std::uint8_t, SHA256_DIGEST_LENGTH> Output{};
            SHA256(reinterpret_cast<const std::uint8_t*>(Bytes.data()), Bytes.size(), Output.data());
            constexpr std::string_view Hex = "0123456789abcdef";
            std::string Result;
            Result.reserve(Output.size() * 2);
            for (const auto Byte : Output)
            {
                Result.push_back(Hex[Byte >> 4]);
                Result.push_back(Hex[Byte & 15]);
            }
            return Result;
        }

        [[nodiscard]] auto LoadAsset(const std::filesystem::path& Root,
            const ResourceDescriptor& Descriptor) -> std::expected<Resource, Prism::Fault::Failure>
        {
            if (!IsResourcePath(Descriptor.Path) ||
                Descriptor.ContentType != ContentTypeFor(Descriptor.Path) || Descriptor.ContentType.empty() ||
                Descriptor.Sha256.size() != 64 || Descriptor.Size > MaxResourceBytes ||
                (Descriptor.Immutable && !Descriptor.Path.starts_with("assets/")))
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            std::error_code Error;
            const auto Path = std::filesystem::canonical(Root / Descriptor.Path, Error);
            if (Error)
                return std::unexpected(Prism::Fault::FromNative(Error));
            const auto Relative = Path.lexically_relative(Root);
            if (Relative.empty() || Relative.is_absolute() || *Relative.begin() == "..")
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Forbidden});
            auto Bytes = ReadFile(Path, MaxResourceBytes);
            if (!Bytes)
                return std::unexpected(Bytes.error());
            if (Bytes->size() != Descriptor.Size || Digest(*Bytes) != Descriptor.Sha256)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            return Resource{Descriptor.Path, Descriptor.ContentType, Descriptor.Sha256, std::move(*Bytes),
                Descriptor.Immutable};
        }
    } // namespace Detail

    /**
     * @brief 启动时只读取固定 catalog.json 及其明确列出的资源并验证全部内容。
     * @param Directory 由启动装配确定的资源根；不接受请求 URL 或客户端文件路径。
     * @return 成功为不可变 catalog，失败为同一次验证的完整 Failure；异常属于启动分配致命边界。
     * @details 同步文件读取仅在启动冷路径执行；所有输入句柄在返回前关闭，无异步取消和半关闭。
     */
    [[nodiscard]] auto LoadCatalog(const std::filesystem::path& Directory)
        -> std::expected<std::shared_ptr<const Catalog>, Prism::Fault::Failure>
    {
        std::error_code Error;
        const auto Root = std::filesystem::canonical(Directory, Error);
        if (Error)
            return std::unexpected(Prism::Fault::FromNative(Error));
        const auto ManifestBytes = Detail::ReadFile(Root / "catalog.json", MaxCatalogBytes);
        if (!ManifestBytes)
            return std::unexpected(ManifestBytes.error());
        ResourceManifest Manifest;
        if (glz::read<Detail::StrictOptions>(Manifest, *ManifestBytes) || Manifest.Version != 1 ||
            Manifest.Assets.empty() || Manifest.Assets.size() > MaxResources)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        std::vector<Resource> Assets;
        Assets.reserve(Manifest.Assets.size());
        std::size_t Total = 0;
        bool HasIndex = false;
        for (const auto& Descriptor : Manifest.Assets)
        {
            for (const auto& Existing : Assets)
                if (Existing.Path == Descriptor.Path)
                    return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
            if (Descriptor.Size > MaxTotalBytes - Total)
                return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::Blocked});
            auto Asset = Detail::LoadAsset(Root, Descriptor);
            if (!Asset)
                return std::unexpected(Asset.error());
            Total += Asset->Body.size();
            if (Asset->Path == "index.html")
                HasIndex = true;
            Assets.push_back(std::move(*Asset));
        }
        if (!HasIndex)
            return std::unexpected(Prism::Fault::Failure{Prism::Fault::Code::BadMessage});
        return std::make_shared<const Catalog>(std::move(Assets));
    }
} // namespace Prism::Operations::Web
