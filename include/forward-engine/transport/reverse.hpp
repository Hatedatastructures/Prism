struct handler_context
{
    session &s_;

    explicit handler_context(session &s)
        : s_(s) {}

    auto &client_socket() 
    { 
        return s_.client_socket_; 
    }
    auto &server_socket() { return s_.server_socket_ptr_; }
    auto &frame_arena() { return s_.frame_arena_; }
    auto &password_verifier() { return s_.password_verifier_; }

    auto connect_upstream(std::string_view label, const protocol::analysis::target &target,
                          bool allow_reverse, bool require_open)
    {
        return s_.connect_upstream(label, target, allow_reverse, require_open);
    }

    auto raw_tunnel() { return s_.raw_tunnel(); }
};