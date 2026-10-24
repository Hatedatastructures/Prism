/** @file Format.cpp @brief DNS wire codec 非模板实现。 */
#include <Prism/Net/Dns/Format.hpp>
#include <Prism/Net/Dns/Detail/Name.hpp>
#include <Prism/Net/Dns/Detail/Record.hpp>

#include <array>
#include <cstring>
#include <unordered_map>
#include <utility>

namespace Prism::Network::Dns
{
    namespace
    {
        auto PutU16(std::vector<std::uint8_t> &Output, const std::uint16_t Value) -> void
        {
            Output.push_back(static_cast<std::uint8_t>(Value >> 8));
            Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
        }

        auto PutU32(std::vector<std::uint8_t> &Output, const std::uint32_t Value) -> void
        {
            Output.push_back(static_cast<std::uint8_t>(Value >> 24));
            Output.push_back(static_cast<std::uint8_t>((Value >> 16) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>((Value >> 8) & 0xFF));
            Output.push_back(static_cast<std::uint8_t>(Value & 0xFF));
        }

        auto AppendName(std::vector<std::uint8_t> &Output, std::string_view Name,
            std::unordered_map<std::string, std::uint16_t> &Compression) -> void
        {
            while (!Name.empty())
            {
                if (const auto It = Compression.find(std::string(Name)); It != Compression.end())
                {
                    PutU16(Output, static_cast<std::uint16_t>(0xC000u | It->second));
                    return;
                }
                if (Output.size() <= 0x3FFF)
                {
                    Compression.emplace(std::string(Name),
                        static_cast<std::uint16_t>(Output.size()));
                }
                const auto Dot = Name.find('.');
                auto Label = Name;
                if (Dot != std::string_view::npos)
                {
                    Label = Name.substr(0, Dot);
                }
                if (Label.empty() || Label.size() > 63)
                {
                    return;
                }
                Output.push_back(static_cast<std::uint8_t>(Label.size()));
                Output.insert(Output.end(), Label.begin(), Label.end());
                if (Dot == std::string_view::npos)
                {
                    break;
                }
                Name = Name.substr(Dot + 1);
            }
            Output.push_back(0);
        }

        auto AppendRecord(std::vector<std::uint8_t> &Output, const Record &RecordValue,
            std::unordered_map<std::string, std::uint16_t> &Compression) -> void
        {
            AppendName(Output, RecordValue.Name, Compression);
            PutU16(Output, static_cast<std::uint16_t>(RecordValue.Type));
            PutU16(Output, RecordValue.RClass);
            PutU32(Output, RecordValue.Ttl);
            PutU16(Output, static_cast<std::uint16_t>(RecordValue.Rdata.size()));
            Output.insert(Output.end(), RecordValue.Rdata.begin(), RecordValue.Rdata.end());
        }

        [[nodiscard]] auto DecodeRecord(
            std::span<const std::uint8_t> Data, std::size_t &Offset)
            -> std::optional<Record>
        {
            Detail::NameCursor Cursor{Data, Offset};
            const auto Parsed = Detail::ReadRecord(Cursor);
            if (!Parsed)
            {
                return std::nullopt;
            }
            Record RecordValue;
            RecordValue.Name = Parsed->Name.View();
            RecordValue.Type = static_cast<QType>(Parsed->Type);
            RecordValue.RClass = Parsed->Class;
            RecordValue.Ttl = Parsed->Ttl;
            RecordValue.Rdata.assign(Parsed->Rdata.begin(), Parsed->Rdata.end());
            Offset = Cursor.Offset;
            return RecordValue;
        }

        [[nodiscard]] auto ReadRecords(Detail::NameCursor &Cursor, const std::uint16_t Count,
            std::vector<Record> &Records) -> bool
        {
            for (std::uint16_t Index = 0; Index < Count; ++Index)
            {
                auto RecordValue = DecodeRecord(Cursor.Data, Cursor.Offset);
                if (!RecordValue)
                {
                    return false;
                }
                Records.push_back(std::move(*RecordValue));
            }
            return true;
        }
    }

    auto ExtractIpv4(const Record &RecordValue)
        -> std::optional<boost::asio::ip::address_v4>
    {
        if (RecordValue.Type != QType::A || RecordValue.Rdata.size() != 4)
        {
            return std::nullopt;
        }
        const auto Raw = static_cast<std::uint32_t>(RecordValue.Rdata[0]) << 24 |
            static_cast<std::uint32_t>(RecordValue.Rdata[1]) << 16 |
            static_cast<std::uint32_t>(RecordValue.Rdata[2]) << 8 |
            static_cast<std::uint32_t>(RecordValue.Rdata[3]);
        return boost::asio::ip::address_v4(Raw);
    }

    auto ExtractIpv6(const Record &RecordValue)
        -> std::optional<boost::asio::ip::address_v6>
    {
        if (RecordValue.Type != QType::Aaaa || RecordValue.Rdata.size() != 16)
        {
            return std::nullopt;
        }
        std::array<unsigned char, 16> Bytes{};
        std::memcpy(Bytes.data(), RecordValue.Rdata.data(), Bytes.size());
        return boost::asio::ip::address_v6(Bytes);
    }

    auto Message::Pack() const -> std::vector<std::uint8_t>
    {
        std::vector<std::uint8_t> Output;
        Output.reserve(512);
        PutU16(Output, Id);

        std::uint16_t Flags = static_cast<std::uint16_t>((Opcode & 0x0Fu) << 11) |
            static_cast<std::uint16_t>(Rcode & 0x0Fu);
        if (Qr) Flags = static_cast<std::uint16_t>(Flags | 0x8000u);
        if (Aa) Flags = static_cast<std::uint16_t>(Flags | 0x0400u);
        if (Tc) Flags = static_cast<std::uint16_t>(Flags | 0x0200u);
        if (Rd) Flags = static_cast<std::uint16_t>(Flags | 0x0100u);
        if (Ra) Flags = static_cast<std::uint16_t>(Flags | 0x0080u);
        PutU16(Output, Flags);
        PutU16(Output, static_cast<std::uint16_t>(Questions.size()));
        PutU16(Output, static_cast<std::uint16_t>(Answers.size()));
        PutU16(Output, static_cast<std::uint16_t>(Authority.size()));
        PutU16(Output, static_cast<std::uint16_t>(Additional.size()));

        std::unordered_map<std::string, std::uint16_t> Compression;
        for (const auto &QuestionValue : Questions)
        {
            AppendName(Output, QuestionValue.Name, Compression);
            PutU16(Output, static_cast<std::uint16_t>(QuestionValue.QueryType));
            PutU16(Output, QuestionValue.QClass);
        }
        for (const auto &RecordValue : Answers) AppendRecord(Output, RecordValue, Compression);
        for (const auto &RecordValue : Authority) AppendRecord(Output, RecordValue, Compression);
        for (const auto &RecordValue : Additional) AppendRecord(Output, RecordValue, Compression);
        return Output;
    }

    auto Message::Unpack(const std::span<const std::uint8_t> Data)
        -> std::optional<Message>
    {
        const auto Header = Detail::ReadHeader(Data);
        if (!Header)
        {
            return std::nullopt;
        }
        Message MessageValue;
        MessageValue.Id = Header->Id;
        const auto Flags = Header->Flags;
        MessageValue.Qr = (Flags & 0x8000u) != 0;
        MessageValue.Opcode = static_cast<std::uint8_t>((Flags >> 11) & 0x0Fu);
        MessageValue.Aa = (Flags & 0x0400u) != 0;
        MessageValue.Tc = (Flags & 0x0200u) != 0;
        MessageValue.Rd = (Flags & 0x0100u) != 0;
        MessageValue.Ra = (Flags & 0x0080u) != 0;
        MessageValue.Rcode = static_cast<std::uint8_t>(Flags & 0x0Fu);

        Detail::NameCursor Cursor{Data, 12};
        for (std::uint16_t Index = 0; Index < Header->Questions; ++Index)
        {
            const auto Parsed = Detail::ReadQuestion(Cursor);
            if (!Parsed)
            {
                return std::nullopt;
            }
            Question QuestionValue;
            QuestionValue.Name = Parsed->Name.View();
            QuestionValue.QueryType = static_cast<QType>(Parsed->Type);
            QuestionValue.QClass = Parsed->Class;
            MessageValue.Questions.push_back(std::move(QuestionValue));
        }
        if (!ReadRecords(Cursor, Header->Answers, MessageValue.Answers) ||
            !ReadRecords(Cursor, Header->Authority, MessageValue.Authority) ||
            !ReadRecords(Cursor, Header->Additional, MessageValue.Additional))
        {
            return std::nullopt;
        }
        return MessageValue;
    }

    auto Message::MakeQuery(const DomainName &Domain, const QType QueryType) -> Message
    {
        Message MessageValue;
        MessageValue.Rd = true;
        Question QuestionValue;
        QuestionValue.Name = Domain.View();
        QuestionValue.QueryType = QueryType;
        MessageValue.Questions.push_back(std::move(QuestionValue));
        return MessageValue;
    }

    auto Message::NormalizeName(const std::string_view Domain) -> std::string
    {
        std::string Output(Domain);
        while (!Output.empty() && Output.back() == '.')
        {
            Output.pop_back();
        }
        for (auto &Character : Output)
        {
            if (Character >= 'A' && Character <= 'Z')
            {
                Character = static_cast<char>(Character - 'A' + 'a');
            }
        }
        return Output;
    }

    auto PackTcp(const Message &MessageValue) -> std::vector<std::uint8_t>
    {
        auto Body = MessageValue.Pack();
        std::vector<std::uint8_t> Output;
        Output.reserve(Body.size() + 2);
        PutU16(Output, static_cast<std::uint16_t>(Body.size()));
        Output.insert(Output.end(), Body.begin(), Body.end());
        return Output;
    }

    auto UnpackTcp(const std::span<const std::uint8_t> Data) -> std::optional<Message>
    {
        if (Data.size() < 2)
        {
            return std::nullopt;
        }
        const auto Length = static_cast<std::size_t>((Data[0] << 8) | Data[1]);
        if (Data.size() < 2 + Length)
        {
            return std::nullopt;
        }
        return Message::Unpack(Data.subspan(2, Length));
    }
} // namespace Prism::Network::Dns
