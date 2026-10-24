/**
 * @file Base64.cpp
 * @brief Base64 编解码实现。
 */
#include <Prism/Foundation/Utility/Crypto/Base64.hpp>

#include <cctype>

namespace Prism::Crypto
{
    auto Base64Decode(const std::string_view Input) -> std::string
    {
        if (Input.empty())
        {
            return {};
        }

        std::string Clean;
        Clean.reserve(Input.size());
        for (const auto Character : Input)
        {
            if (std::isspace(static_cast<std::uint8_t>(Character)))
            {
                continue;
            }
            auto Ch = static_cast<std::uint8_t>(Character);
            if (Ch == '-')
            {
                Ch = '+';
            }
            else if (Ch == '_')
            {
                Ch = '/';
            }
            if (Ch != '=' && Detail::DecTable[Ch] == 255)
            {
                return {};
            }
            Clean.push_back(static_cast<char>(Ch));
        }

        if (Clean.empty() || Clean.size() % 4 != 0)
        {
            return {};
        }

        std::size_t Padding = 0;
        if (Clean.back() == '=')
        {
            ++Padding;
            if (Clean.size() >= 2 && Clean[Clean.size() - 2] == '=')
            {
                ++Padding;
            }
        }
        if (Padding > 2)
        {
            return {};
        }
        const auto DataEnd = Clean.size() - Padding;
        if (Clean.substr(0, DataEnd).find('=') != std::string::npos)
        {
            return {};
        }

        std::string Result;
        Result.reserve((Clean.size() / 4) * 3 - Padding);
        for (std::size_t Offset = 0; Offset < Clean.size(); Offset += 4)
        {
            const auto V0 = Detail::DecTable[static_cast<std::uint8_t>(Clean[Offset])];
            const auto V1 = Detail::DecTable[static_cast<std::uint8_t>(Clean[Offset + 1])];
            if (V0 == 255 || V1 == 255)
            {
                return {};
            }
            const auto IsLast = Offset + 4 == Clean.size();
            const auto C2 = Clean[Offset + 2];
            const auto C3 = Clean[Offset + 3];
            if (C2 == '=')
            {
                if (!IsLast || Padding != 2 || C3 != '=' || (V1 & 0x0F) != 0)
                {
                    return {};
                }
                Result.push_back(static_cast<char>((V0 << 2) | (V1 >> 4)));
                continue;
            }
            const auto V2 = Detail::DecTable[static_cast<std::uint8_t>(C2)];
            if (V2 == 255)
            {
                return {};
            }
            if (C3 == '=')
            {
                if (!IsLast || Padding != 1 || (V2 & 0x03) != 0)
                {
                    return {};
                }
                Result.push_back(static_cast<char>((V0 << 2) | (V1 >> 4)));
                Result.push_back(static_cast<char>(((V1 & 0x0F) << 4) | (V2 >> 2)));
                continue;
            }
            const auto V3 = Detail::DecTable[static_cast<std::uint8_t>(C3)];
            if (V3 == 255 || (Padding != 0 && IsLast))
            {
                return {};
            }
            Result.push_back(static_cast<char>((V0 << 2) | (V1 >> 4)));
            Result.push_back(static_cast<char>(((V1 & 0x0F) << 4) | (V2 >> 2)));
            Result.push_back(static_cast<char>(((V2 & 0x03) << 6) | V3));
        }
        return Result;
    }

    auto Base64Encode(const std::span<const std::uint8_t> Input) -> std::string
    {
        if (Input.empty())
        {
            return {};
        }

        std::string Result;
        Result.reserve(((Input.size() + 2) / 3) * 4);

        std::size_t I = 0;
        const std::size_t FullGroups = Input.size() / 3;

        // 处理完整的 3 字节组
        for (std::size_t G = 0; G < FullGroups; ++G)
        {
            const auto Byte0 = Input[I];
            const auto Byte1 = Input[I + 1];
            const auto Byte2 = Input[I + 2];
            I += 3;

            Result.push_back(Detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(Detail::EncodeTbl[((Byte0 & 0x03) << 4) | (Byte1 >> 4)]);
            Result.push_back(Detail::EncodeTbl[((Byte1 & 0x0F) << 2) | (Byte2 >> 6)]);
            Result.push_back(Detail::EncodeTbl[Byte2 & 0x3F]);
        }

        // 处理剩余字节
        const std::size_t Remaining = Input.size() % 3;
        if (Remaining == 1)
        {
            const auto Byte0 = Input[I];
            Result.push_back(Detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(Detail::EncodeTbl[(Byte0 & 0x03) << 4]);
            Result.push_back('=');
            Result.push_back('=');
        }
        else if (Remaining == 2)
        {
            const auto Byte0 = Input[I];
            const auto Byte1 = Input[I + 1];
            Result.push_back(Detail::EncodeTbl[Byte0 >> 2]);
            Result.push_back(Detail::EncodeTbl[((Byte0 & 0x03) << 4) | (Byte1 >> 4)]);
            Result.push_back(Detail::EncodeTbl[(Byte1 & 0x0F) << 2]);
            Result.push_back('=');
        }

        return Result;
    }
} // namespace Prism::Crypto
