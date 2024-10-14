package mcquery

import "core:os"
import "core:fmt"
import "core:log"
import "core:net"
import "core:strconv"
import "core:math/rand"

import "base:intrinsics"

DEFAULT_PORT :: 25565

// mcquery <hostname[:port] | address[:port]>
main :: proc() {
    log_level := log.Level.Warning

    switch len(os.args) {
    case: usage()
    case 3:
        if os.args[2] != "-verbose" && os.args[2] != "-v" do usage()
        else do log_level = .Debug
        fallthrough
    case 2:
        context.logger = log.create_console_logger(log_level, { .Level, .Terminal_Color })
        for &header in log.Level_Headers {
            header = header[:len(header) - len("--- ")]
        }

        endpoint, err := resolve_server(os.args[1])
        if err != "" {
            log.fatal(err)
            os.exit(1)
        }

        log.debug("Creating udp socket")

        sock, net_err := net.make_unbound_udp_socket(.IP4)
        if net_err != nil do error("Failed creating a socket: %s", net_err)

        defer net.close(sock)
        run(sock, endpoint)
        fmt.println("SUCCESS")
    }
}

usage :: proc() -> ! {
    fmt.eprintfln("Usage: %s <hostname[:port] | address[:port]>", os.args[0])
    os.exit(1)
}

error :: proc(format: string, args: ..any) -> ! {
    fmt.eprintfln(format, ..args)
    os.exit(1)
}

resolve_server :: proc(endpoint_str: string) -> (endpoint: net.Endpoint, err: string) {
    host_or_endpoint, parse_err := net.parse_hostname_or_endpoint(endpoint_str)
    if parse_err != .None {
        return endpoint, fmt.tprint("Failed parsing host or endpoint:", err)
    }

    switch target in host_or_endpoint {
    case net.Endpoint: endpoint = target
    case net.Host:
        dns_records, dns_err := net.get_dns_records_from_os(target.hostname, .IP4)
        if dns_err != {} {
            return endpoint, fmt.tprint("Unable to resolve hostname:", dns_err)
        }
        defer net.destroy_dns_records(dns_records)

        if len(dns_records) == 0 {
            return endpoint, fmt.tprint("Unable to resolve hostname", target.hostname)
        }

        v4_record := dns_records[0].(net.DNS_Record_IP4)
        endpoint.address = v4_record.address
        
        if target.port == 0 { // invalid
            log.info("No port provided, querying dns server..")
            srv_query := fmt.tprintf("_minecraft._tcp.%s.", target.hostname)
            srv_records, dns_err := net.get_dns_records_from_os(srv_query, .SRV)
            if dns_err != {} {
                return endpoint, fmt.tprint("Unable to resolve srv query for port on", srv_query)
            }
            defer net.destroy_dns_records(srv_records)

            if len(srv_records) == 0 {
                return endpoint, fmt.tprint("Unable to find any srv records for", srv_query)
            }
            srv_record := srv_records[0].(net.DNS_Record_SRV)
            endpoint.port = srv_record.port
        }
    }
    return
}

SESSION_ID_MASK :: 0x0f0f0f0f
MAGIC :: 0xfefd
HANDSHAKE :: 9
STAT :: 0

SessionId :: i32be

run :: proc(sock: net.UDP_Socket, endpoint: net.Endpoint) {
    session_id := rand.int31()
    log.debug("Using session id", session_id)
    mc_session_id := SessionId(session_id & SESSION_ID_MASK)

    ctx := Context { sock, endpoint }
    challenge_token := obtain_challenge_token(ctx, mc_session_id)
    log.debug("Received challenge token", challenge_token)
}

Context :: struct {
    sock: net.UDP_Socket,
    endpoint: net.Endpoint,
}

obtain_challenge_token :: proc(ctx: Context, session_id: SessionId) -> ChallengeToken {
    request := ChallengeTokenRequest {
        magic      = MAGIC,
        type       = HANDSHAKE,
        session_id = session_id,
    }
    write_packed(ctx, &request)

    response := read_packed(ctx, ChallengeTokenResponse)
    challenge_token := strconv.parse_uint(string(response.challenge_token)) or_else panic("Invalid token data")

    return ChallengeToken(challenge_token)
}

ChallengeToken :: i32be

ChallengeTokenRequest :: struct #packed {
    magic: u16be,
    type: u8,
    session_id: SessionId,
}

ChallengeTokenResponse :: struct #packed {
    type: u8,
    session_id: SessionId,
    challenge_token: cstring,
}

write_packed :: proc(ctx: Context, data: ^$T) where !intrinsics.type_struct_has_implicit_padding(T) {
    buf := ([^]u8)(data)[:size_of(T)]
    fmt.printfln("Sending %X", buf)
    _, err := net.send(ctx.sock, buf, ctx.endpoint)
    fmt.assertf(err == nil, "Error sending data: %s", err)
}

read_packed :: proc(ctx: Context, $T: typeid) -> T where !intrinsics.type_struct_has_implicit_padding(T) {
    buf: [size_of(T)]u8
    n, _, err := net.recv(ctx.sock, buf[:])
    fmt.assertf(err == nil && n == size_of(T), "Error receiving data %s", err)
    return (^T)(&buf[0])^
}
