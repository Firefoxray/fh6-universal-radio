// fh6-radio-worker: lightweight process that spawns yt-dlp / ffmpeg on behalf
// of the game-injected DLL.  Lives outside the multi-GB game address space so
// the fork() that Wine/Proton performs inside CreateProcess is cheap (~5 MB
// instead of several GB), eliminating the in-game stutter that occurs on every
// track change.
//
// Invocation:  fh6-radio-worker.exe <session-token> [<parent-pid>]
//   token       -- embedded in every pipe name so they are unguessable.
//   parent-pid  -- if given, the worker self-terminates (killing its children)
//                  when that process exits, so nothing is orphaned on a crash.
//
// Protocol: length-prefixed JSON; one connection per request on a multi-instance
//           control pipe, so a slow capture never blocks an audio spawn/kill.
// Data streams: per-pipeline named pipes \\.\pipe\fh6-radio-<token>-<id>-pcm/meta.

#include "fh6/worker/ipc_protocol.hpp"
#include "fh6/subprocess.hpp"

#include <nlohmann/json.hpp>

#include <windows.h>
#include <sddl.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

using json = nlohmann::json;
using namespace fh6::worker;
using namespace fh6::subprocess;

namespace {

std::wstring g_token;                    // session token; set once in main()
SECURITY_ATTRIBUTES* g_pipe_sa = nullptr; // owner-restricted DACL for our pipes

// DACL limiting our pipes to authenticated users + SYSTEM/Admins (never network
// or anonymous). With the random token in the name this blocks squatting and
// injection; on failure the unguessable name alone still protects us.
SECURITY_ATTRIBUTES* make_pipe_sa() {
    static SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;GA;;;AU)(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &sd, nullptr))
        return nullptr;
    sa.nLength              = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle       = FALSE;
    return &sa;
}

// ---------------------------------------------------------------------------
// Pipeline: a set of child processes + proxy threads for one audio track.
// ---------------------------------------------------------------------------

// Bridges a child's stdout (anonymous pipe) to the named pipe the DLL reads.
// The Pipeline owns these handles; the proxy only uses them, so kill() can
// close them race-free once it has joined the thread.
struct ProxyData {
    HANDLE source;       // anonymous pipe read-end (child stdout)
    HANDLE dest;         // named pipe server-end (DLL reads the client end)
    std::wstring name;   // dest's pipe name, for the self-connect unblock
    std::atomic<bool> stop{false};
    ProxyData(HANDLE s, HANDLE d, std::wstring n) : source(s), dest(d), name(std::move(n)) {}
};

struct MetaSink {
    HANDLE dest = nullptr;
    std::wstring name;
    std::mutex mu;
    bool connected = false;
    std::atomic<bool> stop{false};

    MetaSink(HANDLE d, std::wstring n) : dest(d), name(std::move(n)) {}

    bool ensure_connected() {
        std::scoped_lock lk{mu};
        if (connected) return true;
        if (stop.load(std::memory_order_acquire)) return false;
        BOOL ok = ConnectNamedPipe(dest, nullptr)
                      ? TRUE
                      : (GetLastError() == ERROR_PIPE_CONNECTED);
        connected = ok != FALSE;
        return connected;
    }

    void write(std::string_view bytes) {
        if (bytes.empty() || !ensure_connected()) return;
        std::scoped_lock lk{mu};
        if (stop.load(std::memory_order_acquire)) return;
        DWORD written = 0;
        WriteFile(dest, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr);
    }

    void unblock() {
        stop.store(true, std::memory_order_release);
        if (dest) DisconnectNamedPipe(dest);
        if (HANDLE c = CreateFileW(name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0,
                                   nullptr);
            c != INVALID_HANDLE_VALUE)
            CloseHandle(c);
    }

    ~MetaSink() {
        unblock();
        if (dest) {
            CloseHandle(dest);
            dest = nullptr;
        }
    }
};

struct MetaProxyData {
    HANDLE source = nullptr;
    MetaSink* sink = nullptr;
    std::string prefix;
    bool raw = false;
    std::atomic<bool> stop{false};
};

struct Pipeline {
    uint32_t id = 0;
    HANDLE job  = nullptr;
    std::vector<HANDLE> processes;
    std::vector<std::unique_ptr<ProxyData>> proxies_data;
    std::vector<std::thread> proxies;
    std::unique_ptr<MetaSink> meta_sink;
    std::vector<std::unique_ptr<MetaProxyData>> meta_proxies_data;
    std::vector<std::thread> meta_proxies;

    void kill() {
        // 1. Tell the proxies to stop touching their pipes.
        for (auto& pd : proxies_data) pd->stop.store(true, std::memory_order_release);
        for (auto& pd : meta_proxies_data) pd->stop.store(true, std::memory_order_release);

        // 2. Reap the child trees -- this is what unblocks a proxy parked in
        //    ReadFile(source). yt-dlp (PyInstaller) survives a bare
        //    TerminateProcess, so reap() walks the whole tree (Job Objects don't
        //    reap reliably under Wine).
        for (HANDLE& h : processes) reap(h);
        processes.clear();
        if (job) { CloseHandle(job); job = nullptr; }

        // 3. Unblock any proxy still parked on dest. stop is set, so none will
        //    touch dest again; we only break the connection here (close is step
        //    5, post-join), so there's no use-after-close. Parked on WriteFile ->
        //    DisconnectNamedPipe breaks it; parked on ConnectNamedPipe (DLL never
        //    connected) -> a throwaway client completes it.
        for (auto& pd : proxies_data) {
            DisconnectNamedPipe(pd->dest);
            if (HANDLE c = CreateFileW(pd->name.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0,
                                       nullptr);
                c != INVALID_HANDLE_VALUE)
                CloseHandle(c);
        }
        if (meta_sink) meta_sink->unblock();

        // 4. Join -- after this we are the sole owner of every proxy handle.
        for (auto& t : proxies)
            if (t.joinable()) t.join();
        proxies.clear();
        for (auto& t : meta_proxies)
            if (t.joinable()) t.join();
        meta_proxies.clear();

        // 5. Close the pipes (no races now: the proxies have all exited).
        for (auto& pd : proxies_data) {
            DisconnectNamedPipe(pd->dest);
            CloseHandle(pd->dest);
            CloseHandle(pd->source);
        }
        proxies_data.clear();
        for (auto& pd : meta_proxies_data) {
            if (pd->source) CloseHandle(pd->source);
        }
        meta_proxies_data.clear();
        meta_sink.reset();
    }

    ~Pipeline() { kill(); }
};

std::mutex g_mu;
std::mutex g_env_mu;
std::unordered_map<uint32_t, std::unique_ptr<Pipeline>> g_pipelines;

// Kill every child tree, then terminate the worker. Called on an explicit
// shutdown op and on parent-process death.
[[noreturn]] void shutdown_and_exit(UINT code) {
    {
        std::scoped_lock lk{g_mu};
        g_pipelines.clear(); // Pipeline dtors terminate child trees + join proxies
    }
    ExitProcess(code);
}

// ---------------------------------------------------------------------------
// Proxy thread: pump one child's stdout to its named data pipe.
// ---------------------------------------------------------------------------

void proxy_thread_fn(ProxyData* d) {
    // Wait for the DLL to connect its client end (returns immediately if it
    // already has, or once kill()'s self-connect satisfies it).
    if (!d->stop.load(std::memory_order_acquire))
        ConnectNamedPipe(d->dest, nullptr);

    char buf[8192];
    while (!d->stop.load(std::memory_order_acquire)) {
        DWORD got = 0;
        if (!ReadFile(d->source, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        DWORD written = 0;
        if (!WriteFile(d->dest, buf, got, &written, nullptr)) break;
    }

    // Graceful child EOF: flush (so Wine doesn't drop undrained bytes), then
    // disconnect so the DLL's reader sees end-of-track. dest is closed by kill()
    // after the join, never here, so the two never race on it. On kill (stop set)
    // the client is already gone -- leave dest entirely to kill().
    if (!d->stop.load(std::memory_order_acquire)) {
        FlushFileBuffers(d->dest);
        DisconnectNamedPipe(d->dest);
    }
}

void meta_proxy_thread_fn(MetaProxyData* d) {
    char buf[2048];
    std::string pending;
    while (!d->stop.load(std::memory_order_acquire)) {
        DWORD got = 0;
        if (!ReadFile(d->source, buf, sizeof(buf), &got, nullptr) || got == 0) break;
        if (d->raw) {
            d->sink->write({buf, got});
            continue;
        }

        pending.append(buf, got);
        size_t pos = 0;
        while ((pos = pending.find('\n')) != std::string::npos) {
            std::string line = d->prefix + pending.substr(0, pos + 1);
            pending.erase(0, pos + 1);
            d->sink->write(line);
        }
        if (pending.size() > 8192) {
            d->sink->write(d->prefix);
            d->sink->write(pending);
            pending.clear();
        }
    }
    if (!pending.empty() && !d->stop.load(std::memory_order_acquire)) {
        d->sink->write(d->prefix);
        d->sink->write(pending);
        d->sink->write("\n");
    }
}

HANDLE create_stream_pipe(const std::wstring& name, DWORD out_buffer_size = 1 << 20) {
    return CreateNamedPipeW(name.c_str(), PIPE_ACCESS_OUTBOUND, // server writes, client reads
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                            1,                 // max instances
                            out_buffer_size,   // dynamic out buffer
                            0,                 // in buffer (unused for outbound)
                            0,                 // default timeout
                            g_pipe_sa);
}

// ---------------------------------------------------------------------------
// Handle "run" -- run a command and return its captured output. An empty
// output also signals failure to the DLL, which then falls back to a direct
// spawn, so no separate error channel is needed.
// ---------------------------------------------------------------------------

json handle_run(const json& req) {
    const std::wstring cmd    = widen(req.at("cmd").get<std::string>());
    const bool capture_stderr = req.value("capture_stderr", false);
    return {{"ok", true}, {"output", capture_output(cmd, capture_stderr)}};
}

// ---------------------------------------------------------------------------
// Handle "spawn" -- asynchronous pipeline with named-pipe data streams.
// ---------------------------------------------------------------------------

json handle_spawn(const json& req) {
    uint32_t id = req.at("id").get<uint32_t>();
    auto chain  = req.at("chain").get<std::vector<std::string>>();
    if (chain.empty()) return {{"ok", false}, {"error", "empty chain"}};

    bool capture_stderr_meta = req.value("capture_stderr_meta", false);
    int meta_stderr_idx = req.value("meta_stderr_idx", -1);
    if (capture_stderr_meta && meta_stderr_idx == -1) {
        meta_stderr_idx = static_cast<int>(chain.size() - 1);
    }
    std::vector<int> meta_stderr_indices;
    if (req.contains("meta_stderr_indices")) {
        meta_stderr_indices = req.at("meta_stderr_indices").get<std::vector<int>>();
    } else if (meta_stderr_idx >= 0) {
        meta_stderr_indices.push_back(meta_stderr_idx);
    }
    const int raw_meta_stderr_idx = req.value("raw_meta_stderr_idx", meta_stderr_idx);

    DWORD out_buf_size = req.value("out_buffer_size", 1 << 20);
    if (out_buf_size == 0) out_buf_size = 1 << 20;

    auto pl = std::make_unique<Pipeline>();
    pl->id  = id;
    pl->job = create_kill_on_close_job();

    HANDLE nul_in  = open_nul(GENERIC_READ);
    HANDLE err_log = open_stderr_log();

    // Build the chain: each command's stdout feeds the next command's stdin.
    // The last command's stdout goes to a named pipe for the DLL to read.
    HANDLE prev_read = nul_in; // first command reads from NUL
    json resp = {{"ok", true}};

    if (!meta_stderr_indices.empty()) {
        auto meta_name = stream_pipe_name(g_token, id, L"meta");
        HANDLE mnp     = create_stream_pipe(meta_name, 1 << 16);
        if (mnp != INVALID_HANDLE_VALUE) {
            resp["meta_pipe"] = narrow(meta_name);
            pl->meta_sink     = std::make_unique<MetaSink>(mnp, std::move(meta_name));
        }
    }

    std::unique_lock env_lk{g_env_mu};
    std::map<std::wstring, std::wstring> old_env;
    if (req.contains("env") && req["env"].is_object()) {
        for (const auto& [k, v] : req["env"].items()) {
            std::wstring wk = widen(k);
            DWORD need = GetEnvironmentVariableW(wk.c_str(), nullptr, 0);
            if (need > 0) {
                std::wstring old(need, L'\0');
                DWORD got = GetEnvironmentVariableW(wk.c_str(), old.data(), need);
                if (got > 0 && got < need) {
                    old.resize(got);
                    old_env[wk] = old;
                }
            } else {
                old_env[wk] = {};
            }
            SetEnvironmentVariableW(wk.c_str(), widen(v.get<std::string>()).c_str());
        }
    }

    auto restore_env = [&] {
        for (const auto& [k, v] : old_env) {
            SetEnvironmentVariableW(k.c_str(), v.empty() ? nullptr : v.c_str());
        }
    };

    for (size_t i = 0; i < chain.size(); ++i) {
        bool is_last = (i == chain.size() - 1);

        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE rd = nullptr, wr = nullptr;
        if (!CreatePipe(&rd, &wr, &sa, out_buf_size)) {
            restore_env();
            if (prev_read != nul_in) CloseHandle(prev_read);
            if (nul_in) CloseHandle(nul_in);
            if (err_log) CloseHandle(err_log);
            return {{"ok", false}, {"error", "CreatePipe failed"}};
        }

        // The last stage's read-end is consumed by our proxy thread, so it MUST
        // NOT be inherited (otherwise the child holds a writer and EOF never
        // fires). Intermediate read-ends ARE inherited -- they're the next
        // child's stdin.
        if (is_last) SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

        HANDLE cmd_err = err_log;
        bool capture_this_meta =
            std::find(meta_stderr_indices.begin(), meta_stderr_indices.end(),
                      static_cast<int>(i)) != meta_stderr_indices.end() &&
            pl->meta_sink;
        HANDLE meta_err_rd = nullptr;
        
        if (capture_this_meta) {
            HANDLE err_wr = nullptr;
            if (CreatePipe(&meta_err_rd, &err_wr, &sa, 1 << 16)) {
                SetHandleInformation(meta_err_rd, HANDLE_FLAG_INHERIT, 0);
                cmd_err = err_wr;
            }
        }

        std::wstring wcmd = widen(chain[i]);
        HANDLE proc       = spawn_in_job(pl->job, wcmd, prev_read, wr, cmd_err);
        CloseHandle(wr);
        if (capture_this_meta && cmd_err != err_log) {
            CloseHandle(cmd_err);
        }

        // Close the previous read-end now that the child inherited it (unless it
        // was nul_in, which we keep for the side command).
        if (prev_read != nul_in) CloseHandle(prev_read);

        if (!proc) {
            restore_env();
            CloseHandle(rd);
            if (meta_err_rd) CloseHandle(meta_err_rd);
            if (nul_in) CloseHandle(nul_in);
            if (err_log) CloseHandle(err_log);
            return {{"ok", false}, {"error", "spawn failed for step " + std::to_string(i)}};
        }
        pl->processes.push_back(proc);

        if (meta_err_rd && pl->meta_sink) {
            auto mp = std::make_unique<MetaProxyData>();
            mp->source = meta_err_rd;
            mp->sink   = pl->meta_sink.get();
            mp->raw    = static_cast<int>(i) == raw_meta_stderr_idx;
            if (!mp->raw) mp->prefix = "[worker][stderr step " + std::to_string(i) + "] ";
            pl->meta_proxies_data.push_back(std::move(mp));
            pl->meta_proxies.emplace_back(meta_proxy_thread_fn, pl->meta_proxies_data.back().get());
        }

        if (is_last) {
            auto pipe_name = stream_pipe_name(g_token, id, L"pcm");
            HANDLE np      = create_stream_pipe(pipe_name, out_buf_size);
            if (np == INVALID_HANDLE_VALUE) {
                restore_env();
                CloseHandle(rd);
                if (nul_in) CloseHandle(nul_in);
                if (err_log) CloseHandle(err_log);
                return {{"ok", false}, {"error", "CreateNamedPipe failed for pcm"}};
            }
            
            resp["pcm_pipe"] = narrow(pipe_name);
            pl->proxies_data.push_back(std::make_unique<ProxyData>(rd, np, std::move(pipe_name)));
            pl->proxies.emplace_back(proxy_thread_fn, pl->proxies_data.back().get());
        
        } else {
            prev_read = rd; // feed to next command's stdin
        }
    }
    restore_env();
    env_lk.unlock();

    // Optional side command (title resolver): its stdout goes to a separate
    // named pipe so the DLL can drain metadata independently.
    if (req.contains("side_cmd") && !req.at("side_cmd").get<std::string>().empty() &&
        !pl->meta_sink) {
        auto side_u8 = req.at("side_cmd").get<std::string>();
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE srd = nullptr, swr = nullptr;
        if (CreatePipe(&srd, &swr, &sa, 1 << 16)) {
            SetHandleInformation(srd, HANDLE_FLAG_INHERIT, 0);
            std::wstring wcmd = widen(side_u8);
            HANDLE sp         = spawn_in_job(pl->job, wcmd, nul_in, swr, err_log);
            CloseHandle(swr);
            if (sp) {
                pl->processes.push_back(sp);
                auto meta_name = stream_pipe_name(g_token, id, L"meta");
                HANDLE mnp     = create_stream_pipe(meta_name, 1 << 16);
                if (mnp != INVALID_HANDLE_VALUE) {
                    resp["meta_pipe"] = narrow(meta_name);
                    pl->proxies_data.push_back(
                        std::make_unique<ProxyData>(srd, mnp, std::move(meta_name)));
                    pl->proxies.emplace_back(proxy_thread_fn, pl->proxies_data.back().get());
                } else {
                    CloseHandle(srd);
                }
            } else {
                CloseHandle(srd);
            }
        }
    }

    if (nul_in) CloseHandle(nul_in);
    if (err_log) CloseHandle(err_log);

    std::scoped_lock lk{g_mu};
    g_pipelines[id] = std::move(pl);
    return resp;
}

json handle_status(const json& req) {
    uint32_t id = req.at("id").get<uint32_t>();
    std::scoped_lock lk{g_mu};
    auto it = g_pipelines.find(id);
    if (it == g_pipelines.end()) return {{"ok", false}, {"error", "pipeline not found"}};

    std::ostringstream os;
    for (size_t i = 0; i < it->second->processes.size(); ++i) {
        DWORD ec = 0;
        if (GetExitCodeProcess(it->second->processes[i], &ec)) {
            if (i) os << ", ";
            os << "step " << i << "=";
            if (ec == STILL_ACTIVE) os << "running";
            else os << "exit " << ec;
        }
    }
    return {{"ok", true}, {"status", os.str()}};
}

// ---------------------------------------------------------------------------
// Handle "kill" -- terminate a pipeline.
// ---------------------------------------------------------------------------

json handle_kill(const json& req) {
    uint32_t id = req.at("id").get<uint32_t>();
    std::unique_ptr<Pipeline> pl;
    {
        std::scoped_lock lk{g_mu};
        if (auto it = g_pipelines.find(id); it != g_pipelines.end()) {
            pl = std::move(it->second);
            g_pipelines.erase(it);
        }
    }
    // pl's destructor (outside the lock) terminates children + joins threads.
    return {{"ok", true}};
}

// ---------------------------------------------------------------------------
// Serve one control connection: read a request, dispatch, reply, close.
// ---------------------------------------------------------------------------

void serve_connection(HANDLE pipe) {
    auto req_str = ipc_recv(pipe);
    if (!req_str.empty()) {
        json resp;
        try {
            auto msg = json::parse(req_str);
            auto op  = msg.at("op").get<std::string>();
            if (op == "shutdown") {
                ipc_send(pipe, json({{"ok", true}}).dump());
                FlushFileBuffers(pipe);
                DisconnectNamedPipe(pipe);
                CloseHandle(pipe);
                shutdown_and_exit(0); // does not return
            } else if (op == "run") {
                resp = handle_run(msg);
            } else if (op == "spawn") {
                resp = handle_spawn(msg);
            } else if (op == "kill") {
                resp = handle_kill(msg);
            } else if (op == "status") {
                resp = handle_status(msg);
            } else {
                resp = {{"ok", false}, {"error", "unknown op"}};
            }
        } catch (const std::exception& e) {
            resp = {{"ok", false}, {"error", e.what()}};
        }
        ipc_send(pipe, resp.dump());
    }
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}

} // namespace

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char** argv) {
    if (argc < 2) return 2; // session token is mandatory
    g_token    = widen(argv[1]);
    g_pipe_sa  = make_pipe_sa();

    // Self-terminate (taking our children with us) if the game/DLL dies without
    // a clean shutdown, so a crash never leaves yt-dlp/ffmpeg orphaned.
    if (argc >= 3) {
        DWORD parent_pid = std::strtoul(argv[2], nullptr, 10);
        if (HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, parent_pid)) {
            std::thread([parent] {
                WaitForSingleObject(parent, INFINITE);
                CloseHandle(parent);
                shutdown_and_exit(0);
            }).detach();
        }
    }

    // Multi-instance accept loop: every request gets its own connection +
    // handler thread, so a slow capture can't stall an audio spawn/kill.
    const std::wstring ctrl_name = control_pipe_name(g_token);
    for (;;) {
        HANDLE h = CreateNamedPipeW(ctrl_name.c_str(), PIPE_ACCESS_DUPLEX,
                                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                    PIPE_UNLIMITED_INSTANCES, 65536, 65536, 0, g_pipe_sa);
        if (h == INVALID_HANDLE_VALUE) return 1;

        BOOL connected = ConnectNamedPipe(h, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!connected) {
            CloseHandle(h);
            continue;
        }
        std::thread(serve_connection, h).detach();
    }
}
