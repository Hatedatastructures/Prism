/**
 * @file PrismMatrixFileServer.cpp
 * @brief Mihomo 矩阵使用的回环 HTTP 文件目标。
 * @details 只服务显式根目录内的文件，异步处理连接并在回调间持有会话 owner。
 */
#include <boost/asio.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace net = boost::asio;

namespace
{
    constexpr std::size_t MaxRequestBytes = 16 * 1024;
    constexpr std::size_t FileChunkBytes = 64 * 1024;

    [[nodiscard]] auto IsWithinRoot(const std::filesystem::path &Root,
                                    const std::filesystem::path &Target) -> bool
    {
        const auto Relative = Target.lexically_relative(Root);
        return !Relative.empty() && !Relative.is_absolute() && *Relative.begin() != "..";
    }

    class MatrixFileSession final : public std::enable_shared_from_this<MatrixFileSession>
    {
    public:
        MatrixFileSession(net::ip::tcp::socket Socket, std::filesystem::path Root)
            : Socket_(std::move(Socket)), Strand_(net::make_strand(Socket_.get_executor())),
              Root_(std::move(Root))
        {
        }

        auto Start() -> void
        {
            ReadRequest();
        }

    private:
        auto ReadRequest() -> void
        {
            auto Self = shared_from_this();
            net::async_read_until(Socket_, net::dynamic_buffer(Request_, MaxRequestBytes), "\r\n\r\n",
                net::bind_executor(Strand_, [Self](const boost::system::error_code &ErrorCode, std::size_t)
                {
                    if (!ErrorCode)
                    {
                        Self->HandleRequest();
                    }
                }));
        }

        auto HandleRequest() -> void
        {
            const auto LineEnd = Request_.find("\r\n");
            if (LineEnd == std::string::npos)
            {
                SendResponse("400 Bad Request", {});
                return;
            }

            const std::string_view RequestLine(Request_.data(), LineEnd);
            const auto FirstSpace = RequestLine.find(' ');
            const auto SecondSpace = FirstSpace == std::string_view::npos
                                         ? std::string_view::npos
                                         : RequestLine.find(' ', FirstSpace + 1);
            if (FirstSpace == std::string_view::npos || SecondSpace == std::string_view::npos ||
                RequestLine.substr(0, FirstSpace) != "GET")
            {
                SendResponse("400 Bad Request", {});
                return;
            }

            auto RequestPath = RequestLine.substr(FirstSpace + 1, SecondSpace - FirstSpace - 1);
            const auto QueryStart = RequestPath.find('?');
            RequestPath = RequestPath.substr(0, QueryStart);
            if (RequestPath.empty() || RequestPath.front() != '/' ||
                RequestPath.find('\\') != std::string_view::npos)
            {
                SendResponse("404 Not Found", {});
                return;
            }

            std::error_code FileError;
            const auto Candidate = Root_ / std::filesystem::path(RequestPath.substr(1));
            const auto Resolved = std::filesystem::weakly_canonical(Candidate, FileError);
            if (FileError || !IsWithinRoot(Root_, Resolved))
            {
                SendResponse("404 Not Found", {});
                return;
            }

            File_.open(Resolved, std::ios::binary);
            if (!File_.is_open())
            {
                SendResponse("404 Not Found", {});
                return;
            }
            File_.seekg(0, std::ios::end);
            const auto Size = File_.tellg();
            File_.seekg(0, std::ios::beg);
            if (Size < 0)
            {
                SendResponse("500 Internal Server Error", {});
                return;
            }

            Response_ = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                        std::to_string(Size) + "\r\nConnection: close\r\n\r\n";
            WriteResponse();
        }

        auto SendResponse(std::string_view Status, std::string_view Body) -> void
        {
            if (File_.is_open())
            {
                File_.close();
            }
            Response_ = "HTTP/1.1 " + std::string(Status) + "\r\nContent-Length: " +
                        std::to_string(Body.size()) + "\r\nConnection: close\r\n\r\n" + std::string(Body);
            WriteResponse();
        }

        auto WriteResponse() -> void
        {
            auto Self = shared_from_this();
            net::async_write(Socket_, net::buffer(Response_),
                net::bind_executor(Strand_, [Self](const boost::system::error_code &ErrorCode, std::size_t)
                {
                    if (!ErrorCode && Self->File_.is_open())
                    {
                        Self->WriteFileChunk();
                    }
                }));
        }

        auto WriteFileChunk() -> void
        {
            auto Self = shared_from_this();
            File_.read(FileBuffer_.data(), static_cast<std::streamsize>(FileBuffer_.size()));
            const auto BytesRead = static_cast<std::size_t>(File_.gcount());
            if (BytesRead == 0)
            {
                return;
            }
            net::async_write(Socket_, net::buffer(FileBuffer_.data(), BytesRead),
                net::bind_executor(Strand_, [Self](const boost::system::error_code &ErrorCode, std::size_t)
                {
                    if (!ErrorCode)
                    {
                        Self->WriteFileChunk();
                    }
                }));
        }

        net::ip::tcp::socket Socket_;
        net::strand<net::any_io_executor> Strand_;
        std::filesystem::path Root_;
        std::string Request_;
        std::string Response_;
        std::array<char, FileChunkBytes> FileBuffer_{};
        std::ifstream File_;
    };
} // namespace

auto main(int ArgumentCount, char **Arguments) -> int
{
    if (ArgumentCount < 2)
    {
        std::cerr << "usage: PrismMatrixFileServer <root_dir> [port] [threads]\n";
        return 1;
    }

    try
    {
        const auto Root = std::filesystem::canonical(Arguments[1]);
        const auto PortValue = ArgumentCount > 2 ? std::stoul(Arguments[2]) : 18080UL;
        const auto ThreadValue = ArgumentCount > 3 ? std::stoul(Arguments[3]) : 8UL;
        if (PortValue == 0 || PortValue > 65535 || ThreadValue == 0 || ThreadValue > 64)
        {
            std::cerr << "port must be 1..65535 and threads must be 1..64\n";
            return 2;
        }

        net::io_context IoContext;
        net::ip::tcp::acceptor Acceptor(
            IoContext, net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"),
                                              static_cast<std::uint16_t>(PortValue)));

        auto AcceptNext = [&](auto &&Self) -> void
        {
            Acceptor.async_accept(IoContext,
                [&, Self = std::forward<decltype(Self)>(Self)]
                (const boost::system::error_code &ErrorCode, net::ip::tcp::socket Socket) mutable
                {
                    if (ErrorCode)
                    {
                        return;
                    }
                    std::make_shared<MatrixFileSession>(std::move(Socket), Root)->Start();
                    Self(Self);
                });
        };
        AcceptNext(AcceptNext);

        std::vector<std::thread> ThreadPool;
        ThreadPool.reserve(static_cast<std::size_t>(ThreadValue));
        for (unsigned long Index = 0; Index < ThreadValue; ++Index)
        {
            ThreadPool.emplace_back([&IoContext] { IoContext.run(); });
        }
        std::cerr << "Prism matrix file server listening on " << PortValue << ", root="
                  << Root.string() << ", threads=" << ThreadValue << '\n';
        for (auto &Thread : ThreadPool)
        {
            Thread.join();
        }
    }
    catch (const std::exception &Failure)
    {
        std::cerr << "Prism matrix file server failed: " << Failure.what() << '\n';
        return 3;
    }
    return 0;
}
