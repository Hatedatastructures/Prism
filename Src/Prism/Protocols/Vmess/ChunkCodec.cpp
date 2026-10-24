/**
 * @file ChunkCodec.cpp
 * @brief VMess 分块加密、解密和 SHAKE 掩码实现。
 */

#include <Prism/Protocols/Vmess/ChunkCodec.hpp>
#include <Prism/Protocols/Vmess/ChunkMask.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace Prism::Vmess
{
    namespace detail
    {
        auto IncNonce(std::span<std::uint8_t, 12> Nonce) -> void
        {
            for (std::size_t I = Nonce.size(); I > 0; --I)
            {
                if (++Nonce[I - 1] != 0)
                {
                    break;
                }
            }
        }

        [[nodiscard]] auto HasOption(std::uint8_t Options, Option Value) noexcept -> bool
        {
            return (Options & static_cast<std::uint8_t>(Value)) != 0;
        }

        [[nodiscard]] auto MakeNonce(std::uint16_t Count, std::span<const std::uint8_t, 16> Seed)
            -> std::array<std::uint8_t, 12>
        {
            std::array<std::uint8_t, 12> Nonce{};
            Nonce[0] = static_cast<std::uint8_t>(Count >> 8);
            Nonce[1] = static_cast<std::uint8_t>(Count & 0xFF);
            std::memcpy(Nonce.data() + 2, Seed.data() + 2, 10);
            return Nonce;
        }
    } // namespace detail

    ChunkEncryptor::ChunkEncryptor(std::span<const std::uint8_t, 16> Key,
        std::span<const std::uint8_t, 12> Nonce)
        : Key_(), NonceSeed_(), LegacyNonce_(), Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key),
          Options_(static_cast<std::uint8_t>(Option::AuthenticatedLength))
    {
        std::memcpy(Key_.data(), Key.data(), 16);
        std::memcpy(NonceSeed_.data(), Nonce.data(), 12);
        std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
    }

    ChunkEncryptor::ChunkEncryptor(std::span<const std::uint8_t, 16> Key,
        std::span<const std::uint8_t, 16> Nonce, std::uint8_t OptionsValue)
        : Key_(), NonceSeed_(), LegacyNonce_(), Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key),
          Options_(OptionsValue)
    {
        std::memcpy(Key_.data(), Key.data(), 16);
        std::memcpy(NonceSeed_.data(), Nonce.data(), 16);
        std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
        if (detail::HasOption(Options_, Option::ChunkMasking))
        {
            MaskStream_.emplace(std::span<const std::uint8_t>(NonceSeed_));
        }
    }

    auto ChunkEncryptor::Seal(std::span<const std::uint8_t> Plain, std::span<std::uint8_t> Out) -> std::size_t
    {
        const auto N = Plain.size();
        if (Finished_ || N > MaxChunkLen ||
            N > (std::numeric_limits<std::size_t>::max)() - Overhead || Out.size() < N + Overhead)
        {
            return 0;
        }

        if (!UseAuthenticatedLength())
        {
            const auto CipherLength = N + 16;
            if (CipherLength > 0xFFFF)
            {
                return 0;
            }
            auto WireLength = static_cast<std::uint16_t>(CipherLength);
            WireLength ^= NextMask();
            Out[0] = static_cast<std::uint8_t>(WireLength >> 8);
            Out[1] = static_cast<std::uint8_t>(WireLength & 0xFF);
            const auto Nonce = detail::MakeNonce(NonceCount_, NonceSeed_);
            if (!SealChunk(Nonce, Plain, Out.subspan(2)))
            {
                return 0;
            }
            ++NonceCount_;
            return 2 + CipherLength;
        }

        if (N == AuthenticatedLengthEofMarker ||
            N > (std::numeric_limits<std::uint16_t>::max)())
        {
            return 0;
        }

        std::array<std::uint8_t, 2> LenPlain{};
        LenPlain[0] = static_cast<std::uint8_t>((N >> 8) & 0xFF);
        LenPlain[1] = static_cast<std::uint8_t>(N & 0xFF);
        std::array<std::uint8_t, 2 + 16> LenEnc{};
        auto NextNonce = LegacyNonce_;
        if (!SealChunk(NextNonce, LenPlain, LenEnc))
        {
            return 0;
        }
        detail::IncNonce(NextNonce);

        std::memcpy(Out.data(), LenEnc.data(), LenEnc.size());
        if (!SealChunk(NextNonce, Plain, Out.subspan(LenEnc.size())))
        {
            return 0;
        }
        detail::IncNonce(NextNonce);
        LegacyNonce_ = NextNonce;
        return LenEnc.size() + N + 16;
    }

    auto ChunkEncryptor::Finish(std::span<std::uint8_t> Out) -> std::size_t
    {
        if (Finished_)
        {
            return 0;
        }
        if (UseAuthenticatedLength())
        {
            constexpr auto HeaderSize = std::size_t{18};
            if (Out.size() < HeaderSize)
            {
                return 0;
            }
            const std::array<std::uint8_t, 2> Length{
                static_cast<std::uint8_t>(AuthenticatedLengthEofMarker >> 8U),
                static_cast<std::uint8_t>(AuthenticatedLengthEofMarker & 0xFFU)};
            auto NextNonce = LegacyNonce_;
            if (!SealChunk(NextNonce, Length, Out.first(HeaderSize)))
            {
                return 0;
            }
            detail::IncNonce(NextNonce);
            LegacyNonce_ = NextNonce;
            Finished_ = true;
            return HeaderSize;
        }
        if (Out.size() < 2)
        {
            return 0;
        }
        auto WireLength = NextMask();
        Out[0] = static_cast<std::uint8_t>(WireLength >> 8);
        Out[1] = static_cast<std::uint8_t>(WireLength & 0xFF);
        Finished_ = true;
        return 2;
    }

    [[nodiscard]] auto ChunkEncryptor::SealChunk(std::span<const std::uint8_t> Nonce,
        std::span<const std::uint8_t> Plain, std::span<std::uint8_t> Out) -> bool
    {
        return Aead_.Seal(Prism::Crypto::SealInput{Out, Plain, Nonce, {}}) == Prism::Fault::Code::Success;
    }

    [[nodiscard]] auto ChunkEncryptor::UseAuthenticatedLength() const noexcept -> bool
    {
        return detail::HasOption(Options_, Option::AuthenticatedLength);
    }

    [[nodiscard]] auto ChunkEncryptor::NextMask() -> std::uint16_t
    {
        if (!MaskStream_)
        {
            return 0;
        }
        std::array<std::uint8_t, 2> Mask{};
        MaskStream_->Take(Mask);
        return static_cast<std::uint16_t>(Mask[0]) << 8 | Mask[1];
    }

    ChunkDecryptor::ChunkDecryptor(std::span<const std::uint8_t, 16> Key,
        std::span<const std::uint8_t, 12> Nonce)
        : Key_(), NonceSeed_(), LegacyNonce_(), Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key),
          Options_(static_cast<std::uint8_t>(Option::AuthenticatedLength))
    {
        std::memcpy(Key_.data(), Key.data(), 16);
        std::memcpy(NonceSeed_.data(), Nonce.data(), 12);
        std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
    }

    ChunkDecryptor::ChunkDecryptor(std::span<const std::uint8_t, 16> Key,
        std::span<const std::uint8_t, 16> Nonce, std::uint8_t OptionsValue)
        : Key_(), NonceSeed_(), LegacyNonce_(), Aead_(Prism::Crypto::AeadCipher::Aes128Gcm, Key),
          Options_(OptionsValue)
    {
        std::memcpy(Key_.data(), Key.data(), 16);
        std::memcpy(NonceSeed_.data(), Nonce.data(), 16);
        std::memcpy(LegacyNonce_.data(), Nonce.data(), 12);
        if (detail::HasOption(Options_, Option::ChunkMasking))
        {
            MaskStream_.emplace(std::span<const std::uint8_t>(NonceSeed_));
        }
    }

    auto ChunkDecryptor::OpenLen(std::span<const std::uint8_t> Head) -> std::expected<std::size_t, Error>
    {
        if (Finished_)
        {
            return std::unexpected(Error::ProtocolError);
        }
        if (!UseAuthenticatedLength())
        {
            if (Head.size() < 2)
            {
                return std::unexpected(Error::NeedMore);
            }
            std::uint16_t Length = static_cast<std::uint16_t>(Head[0]) << 8 | Head[1];
            Length ^= NextMask();
            if (Length > MaxChunkLen + 16)
            {
                return std::unexpected(Error::BadLength);
            }
            if (Length == 0U)
            {
                Finished_ = true;
            }
            return Length;
        }
        if (Head.size() < 18)
        {
            return std::unexpected(Error::NeedMore);
        }
        std::array<std::uint8_t, 2> LenPlain{};
        if (!OpenChunk(LegacyNonce_, Head.first(18), LenPlain))
        {
            return std::unexpected(Error::BadAuth);
        }
        detail::IncNonce(LegacyNonce_);
        const auto N = static_cast<std::size_t>(LenPlain[0]) << 8 | LenPlain[1];
        if (N == AuthenticatedLengthEofMarker)
        {
            Finished_ = true;
            return N;
        }
        if (N > MaxChunkLen)
        {
            return std::unexpected(Error::BadLength);
        }
        return N;
    }

    auto ChunkDecryptor::OpenPayload(std::span<const std::uint8_t> Data, std::span<std::uint8_t> Out) -> Error
    {
        if (Finished_)
        {
            return Error::ProtocolError;
        }
        if (Data.size() < 16 || Out.size() < Data.size() - 16)
        {
            return Error::NeedMore;
        }
        if (UseAuthenticatedLength())
        {
            if (!OpenChunk(LegacyNonce_, Data, Out.first(Data.size() - 16)))
            {
                return Error::BadAuth;
            }
            detail::IncNonce(LegacyNonce_);
            return Error::None;
        }
        const auto Nonce = detail::MakeNonce(NonceCount_, NonceSeed_);
        if (!OpenChunk(Nonce, Data, Out.first(Data.size() - 16)))
        {
            return Error::BadAuth;
        }
        ++NonceCount_;
        return Error::None;
    }

    auto ChunkDecryptor::Open(std::span<const std::uint8_t> Data, std::span<std::uint8_t> Out,
        std::size_t& Consumed) -> Error
    {
        Consumed = 0;
        if (Finished_)
        {
            return Error::ProtocolError;
        }
        const bool AuthenticatedLength = UseAuthenticatedLength();
        std::size_t Minimum = 2;
        if (AuthenticatedLength)
        {
            Minimum = 18;
        }
        if (Data.size() < Minimum)
        {
            return Error::NeedMore;
        }
        const auto SavedLegacyNonce = LegacyNonce_;
        const auto SavedNonceCount = NonceCount_;
        const auto SavedMaskStream = MaskStream_;
        const auto RestoreState = [this, SavedLegacyNonce, SavedNonceCount, SavedMaskStream]() -> void
        {
            LegacyNonce_ = SavedLegacyNonce;
            NonceCount_ = SavedNonceCount;
            MaskStream_ = SavedMaskStream;
        };
        auto Len = OpenLen(Data);
        if (!Len)
        {
            RestoreState();
            return Len.error();
        }
        if ((AuthenticatedLength && *Len == AuthenticatedLengthEofMarker) ||
            (!AuthenticatedLength && *Len == 0))
        {
            Consumed = Minimum;
            return Error::None;
        }
        const auto Prefix = Minimum;
        auto PayloadLength = *Len;
        if (AuthenticatedLength)
        {
            PayloadLength += 16;
        }
        if (Data.size() < Prefix + PayloadLength)
        {
            RestoreState();
            return Error::NeedMore;
        }
        const auto Ec = OpenPayload(Data.subspan(Prefix, PayloadLength), Out);
        if (Ec != Error::None)
        {
            RestoreState();
            return Ec;
        }
        Consumed = Prefix + PayloadLength;
        return Error::None;
    }

    [[nodiscard]] auto ChunkDecryptor::OpenChunk(std::span<const std::uint8_t> Nonce,
        std::span<const std::uint8_t> Cipher, std::span<std::uint8_t> Out) -> bool
    {
        return Aead_.Open(Prism::Crypto::OpenInput{Out, Cipher, Nonce, {}}) == Prism::Fault::Code::Success;
    }

    [[nodiscard]] auto ChunkDecryptor::UseAuthenticatedLength() const noexcept -> bool
    {
        return detail::HasOption(Options_, Option::AuthenticatedLength);
    }

    [[nodiscard]] auto ChunkDecryptor::NextMask() -> std::uint16_t
    {
        if (!MaskStream_)
        {
            return 0;
        }
        std::array<std::uint8_t, 2> Mask{};
        MaskStream_->Take(Mask);
        return static_cast<std::uint16_t>(Mask[0]) << 8 | Mask[1];
    }

    auto ChunkStream::Init(std::span<const std::uint8_t, 16> Key, std::span<const std::uint8_t, 16> Iv)
        -> void
    {
        std::array<std::uint8_t, 12> Nonce{};
        std::memcpy(Nonce.data(), Iv.data(), 12);
        Enc_ = ChunkEncryptor(Key, Nonce);
        Dec_ = ChunkDecryptor(Key, Nonce);
    }

    auto ChunkStream::Encrypt(std::span<const std::uint8_t> Payload, std::string& Wire) -> bool
    {
        if (Payload.size() > (std::numeric_limits<std::size_t>::max)() - ChunkEncryptor::Overhead)
        {
            Wire.clear();
            return true;
        }
        std::vector<std::uint8_t> Out(Payload.size() + ChunkEncryptor::Overhead);
        const auto N = Payload.empty()
            ? Enc_.Finish(Out)
            : Enc_.Seal(Payload, Out);
        if (N == 0)
        {
            Wire.clear();
            return true;
        }
        Wire.assign(reinterpret_cast<const char*>(Out.data()), N);
        return false;
    }

    auto ChunkStream::Decrypt(std::span<const std::uint8_t> Wire, std::string& Plain) -> Result
    {
        Result R;
        std::vector<std::uint8_t> Out(Wire.size());
        std::size_t Consumed = 0;
        const auto Ec = Dec_.Open(Wire, Out, Consumed);
        if (Ec != Error::None)
        {
            R.Ec = make_error_code(Ec);
            return R;
        }
        std::size_t PlainLength = 0;
        if (Consumed >= 18 + 16)
        {
            PlainLength = Consumed - 18 - 16;
        }
        Plain.assign(reinterpret_cast<const char*>(Out.data()), PlainLength);
        R.Consumed = Consumed;
        return R;
    }

    ShakeStream::ShakeStream(std::span<const std::uint8_t> Seed)
    {
        std::size_t Offset = 0;
        auto* Block = reinterpret_cast<std::uint8_t*>(State_.data());
        while (Seed.size() - Offset >= Rate)
        {
            for (std::size_t Index = 0; Index < Rate; ++Index)
            {
                Block[Index] ^= Seed[Offset + Index];
            }
            Permute(State_);
            Offset += Rate;
        }
        const auto Remaining = Seed.size() - Offset;
        for (std::size_t Index = 0; Index < Remaining; ++Index)
        {
            Block[Index] ^= Seed[Offset + Index];
        }
        Block[Remaining] ^= 0x1F;
        Block[Rate - 1] ^= 0x80;
        Permute(State_);
    }

    auto ShakeStream::Take(std::span<std::uint8_t> Output) -> void
    {
        std::size_t Offset = 0;
        while (Offset < Output.size())
        {
            if (Cursor_ == Rate)
            {
                std::memcpy(Buffer_.data(), State_.data(), Rate);
                Permute(State_);
                Cursor_ = 0;
            }
            const auto Count = (std::min)(Rate - Cursor_, Output.size() - Offset);
            std::memcpy(Output.data() + Offset, Buffer_.data() + Cursor_, Count);
            Cursor_ += Count;
            Offset += Count;
        }
    }

    auto ShakeStream::Permute(std::array<std::uint64_t, 25>& State) noexcept -> void
    {
        static constexpr std::array<int, 24> Piln{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13,
            12, 2, 20, 14, 22, 9, 6, 1};
        static constexpr std::array<int, 24> Rotc{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8,
            25, 43, 62, 18, 39, 61, 20, 44};
        for (const auto RoundConstant : RoundConstants)
        {
            std::array<std::uint64_t, 5> Column{};
            for (std::size_t Index = 0; Index < 5; ++Index)
            {
                Column[Index] = State[Index] ^ State[Index + 5] ^ State[Index + 10] ^ State[Index + 15] ^
                    State[Index + 20];
            }
            for (std::size_t Index = 0; Index < 5; ++Index)
            {
                const auto Delta = Column[(Index + 4) % 5] ^ Rotate(Column[(Index + 1) % 5], 1);
                for (std::size_t Row = 0; Row < 25; Row += 5)
                {
                    State[Row + Index] ^= Delta;
                }
            }
            auto Temporary = State[1];
            for (std::size_t Index = 0; Index < Piln.size(); ++Index)
            {
                const auto Position = static_cast<std::size_t>(Piln[Index]);
                const auto Saved = State[Position];
                State[Position] = Rotate(Temporary, Rotc[Index]);
                Temporary = Saved;
            }
            for (std::size_t Row = 0; Row < 25; Row += 5)
            {
                std::array<std::uint64_t, 5> Saved{};
                for (std::size_t Index = 0; Index < 5; ++Index)
                {
                    Saved[Index] = State[Row + Index];
                }
                for (std::size_t Index = 0; Index < 5; ++Index)
                {
                    State[Row + Index] = Saved[Index] ^ ((~Saved[(Index + 1) % 5]) & Saved[(Index + 2) % 5]);
                }
            }
            State[0] ^= RoundConstant;
        }
    }

} // namespace Prism::Vmess
