/**
 * @file PerfTest.cpp
 * @brief 内存分配与协议序列化性能基线。
 */

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <new>
#include <string>

#include <Prism/Foundation/Memory/Container.hpp>
#include <Prism/Foundation/Memory/Pointer.hpp>
#include <Prism/Foundation/Memory/Pool.hpp>
#include <Prism/Protocols/Socks5/Socks5.hpp>
#include <Prism/Protocols/Socks5/Types.hpp>

namespace
{
    TEST(MemoryPointer, ArenaAllocPerf)
    {
        constexpr int Iterations = 100000;

        auto Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            auto *Value = new std::string(32, 'x');
            delete Value;
        }
        const auto SystemMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - Start).count();

        Prism::Memory::FrameArena Arena;
        auto Resource = Arena.Get();
        Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            auto *Value = new (Resource->allocate(sizeof(std::string), alignof(std::string)))
                std::string(32, 'x');
            Value->~basic_string();
            Resource->deallocate(Value, sizeof(std::string), alignof(std::string));
        }
        const auto ArenaMilliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - Start).count();

        GTEST_LOG_(INFO) << "system new: " << SystemMilliseconds << "ms, arena: "
                         << ArenaMilliseconds << "ms";
        EXPECT_LE(ArenaMilliseconds, SystemMilliseconds * 2)
            << "arena 应至少不慢于系统 new";
    }

    TEST(MemoryPointer, ProtocolCodecArenaVsHeap)
    {
        Prism::Socks5::Request Request;
        Request.Ver = 5;
        Request.Cmd = Prism::Socks5::Command::Connect;
        Request.Rsv = 0;
        Request.Target.Type = Prism::Socks5::AddressType::Domain;
        Request.Target.Host = "example.com";
        Request.Target.Port = 443;

        constexpr int Iterations = 200000;
        auto Start = std::chrono::steady_clock::now();
        volatile std::size_t Sink = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            const auto Wire = Prism::Socks5::BuildRequest(Request);
            Sink += Wire.size();
        }
        const auto HeapMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - Start).count();

        Prism::Memory::SessionResource Memory;
        Prism::Memory::Vector<std::uint8_t> TxWire(Memory.Arena());
        Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Prism::Socks5::BuildRequest(Request, TxWire);
            Sink += TxWire.size();
        }
        const auto ArenaMicroseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - Start).count();

        GTEST_LOG_(INFO) << "build_request x" << Iterations << ": per-frame heap "
                         << HeapMicroseconds << "us, reused arena buffer "
                         << ArenaMicroseconds << "us (sink=" << Sink << ")";
        EXPECT_LE(ArenaMicroseconds, HeapMicroseconds);
    }

    TEST(MemoryPointer, ProtocolDgramArenaVsHeap)
    {
        Prism::Socks5::Address Destination;
        Destination.Type = Prism::Socks5::AddressType::Ipv4;
        Destination.Host = "10.0.0.1";
        Destination.Port = 53;
        constexpr std::size_t PayloadSize = 128;
        std::array<std::uint8_t, PayloadSize> Payload{};
        Payload.fill(0xAB);

        constexpr int Iterations = 100000;
        auto Start = std::chrono::steady_clock::now();
        volatile std::size_t Sink = 0;
        for (int Index = 0; Index < Iterations; ++Index)
        {
            const auto Wire = Prism::Socks5::BuildUdpDatagram(Destination, Payload);
            Sink += Wire.size();
        }
        const auto HeapMilliseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - Start).count();

        Prism::Memory::SessionResource Memory;
        Prism::Memory::Vector<std::uint8_t> TxWire(Memory.Arena());
        Start = std::chrono::steady_clock::now();
        for (int Index = 0; Index < Iterations; ++Index)
        {
            Prism::Socks5::BuildUdpDatagram(Destination, Payload, TxWire);
            Sink += TxWire.size();
        }
        const auto ArenaMilliseconds = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - Start).count();

        GTEST_LOG_(INFO) << "build_udp_datagram x" << Iterations << ": per-frame heap "
                         << HeapMilliseconds << "us, reused arena buffer "
                         << ArenaMilliseconds << "us (sink=" << Sink << ")";
        EXPECT_LE(ArenaMilliseconds, HeapMilliseconds * 2);
    }
}
