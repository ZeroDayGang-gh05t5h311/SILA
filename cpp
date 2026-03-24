#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <queue>
#include <fstream>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
using namespace std::chrono;
// Default ports for common services
static const std::map<int, std::string> DEFAULT_PORTS = {
    {21, "ftp"},         // FTP
    {22, "ssh"},         // SSH
    {23, "telnet"},      // Telnet
    {25, "smtp"},        // SMTP
    {53, "dns"},         // DNS
    {80, "http"},        // HTTP
    {443, "https"},      // HTTPS
    {3306, "mysql"},     // MySQL
    {3309, "mysql (Cluster)"}, // MySQL Cluster
    {5432, "postgresql"}, // PostgreSQL
    {6379, "redis"},     // Redis
    {27017, "mongodb"},  // MongoDB
    {5984, "couchdb"},   // CouchDB
    {8080, "http-alt"},  // HTTP alternative (used by Tomcat, Nginx, etc.)
    {8443, "https-alt"}, // HTTPS alternative (used by some Tomcat configurations)
    {11211, "memcached"}, // Memcached
    {21, "ftp"},         // FTP
    {2222, "ssh-alt"},   // SSH alternative (used by some VPS and cloud providers)
    {5000, "flask"},     // Flask (default for web development)
    {6379, "redis"},     // Redis
    {9000, "php-fpm"},   // PHP-FPM
    {10000, "webmin"},   // Webmin
    {25565, "minecraft"} // Minecraft (gaming)
};
// Max bytes to read for banners
static const size_t BANNER_READ_BYTES = 4096;

// Struct to store scan result
struct ScanResult {
    std::string host;
    int port;
    std::string service_guess;
    bool reachable = false;
    std::string banner;
    std::map<std::string, std::string> http_headers;
    std::vector<std::string> notes;
    double duration_s = 0.0;
};

// Socket timeout setter
static bool set_socket_timeout(int sockfd, double seconds) {
    struct timeval tv;
    tv.tv_sec = static_cast<int>(seconds);
    tv.tv_usec = static_cast<int>((seconds - tv.tv_sec) * 1e6);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return false;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return true;
}

// Function to receive banner and other data from socket
static std::string recv_all(int sockfd, double timeout, size_t max_bytes = BANNER_READ_BYTES) {
    set_socket_timeout(sockfd, timeout);
    std::string buffer;
    char tmp[2048];
    while (buffer.size() < max_bytes) {
        ssize_t n = recv(sockfd, tmp, sizeof(tmp), 0);
        if (n > 0) {
            buffer.append(tmp, n);
            if (buffer.find("\r\n\r\n") != std::string::npos) break;
        } else {
            break;
        }
    }
    return buffer;
}
static void parse_http_response(const std::string& data,
                                std::map<std::string, std::string>& headers,
                                std::vector<std::string>& notes) {
    std::istringstream ss(data);
    std::string line;
    if (!std::getline(ss, line)) return;

    if (!line.empty() && line.back() == '\r') line.pop_back();
    headers["status_line"] = line;

    std::istringstream sl(line);
    std::string httpver;
    int status = 0;
    std::string reason;
    if (sl >> httpver >> status) {
        std::getline(sl, reason);
        if (!reason.empty() && reason[0] == ' ') reason.erase(0, 1);
        headers["status_code"] = std::to_string(status);
        headers["reason"] = reason;
        if (status != 200) notes.push_back("HTTP non-200 status: " + std::to_string(status));
    } else {
        notes.push_back("Malformed HTTP status line");
        return;
    }

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        size_t a = val.find_first_not_of(" \t");
        if (a != std::string::npos) val = val.substr(a);
        headers[key] = val;
    }
}
static void probe_https(int sockfd, const std::string& host, double timeout, ScanResult& out) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        out.notes.push_back("SSL_CTX_new failed");
        return;
    }
    const unsigned char alpn_protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        out.notes.push_back("TLS handshake failed");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }
    out.reachable = true;
    out.notes.push_back("TLS version: " + std::string(SSL_get_version(ssl)));
    const char* cipher = SSL_get_cipher(ssl);
    if (cipher) out.notes.push_back("Cipher: " + std::string(cipher));

    const unsigned char* proto = nullptr;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);
    if (proto_len > 0)
        out.notes.push_back("ALPN protocol: " + std::string(reinterpret_cast<const char*>(proto), proto_len));

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        char* iss = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        if (subj) out.notes.push_back(std::string("TLS Subject: ") + subj);
        if (iss) out.notes.push_back(std::string("TLS Issuer: ") + iss);
        OPENSSL_free(subj);
        OPENSSL_free(iss);
        X509_free(cert);
    }

    std::ostringstream req;
    req << "HEAD / HTTP/1.1\r\nHost: " << host
        << "\r\nUser-Agent: banner-scanner/1.0\r\n\r\n";
    SSL_write(ssl, req.str().c_str(), req.str().size());
    char buf[2048];
    std::string data;
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        data.append(buf, n);
        if (data.find("\r\n\r\n") != std::string::npos) break;
    }
    out.banner = data;
    parse_http_response(data, out.http_headers, out.notes);

    auto it = out.http_headers.find("Server");
    if (it != out.http_headers.end()) {
        std::string srv = it->second;
        if (srv.find("Apache") != std::string::npos) srv = "Apache";
        else if (srv.find("nginx") != std::string::npos) srv = "nginx";
        else if (srv.find("Microsoft-IIS") != std::string::npos) srv = "IIS";
        out.notes.push_back("Normalized server: " + srv);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
static ScanResult probe_tcp_banner(const std::string& host, int port, double timeout) {
    std::string userAgent = "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.166 Safari/537.36\r\n\r\n";
    ScanResult out;
    out.host = host;
    out.port = port;
    out.service_guess = DEFAULT_PORTS.at(port);
    auto start = high_resolution_clock::now();
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return out;

    int sockfd = -1;
    for (auto rp = res; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;
        if (rp->ai_family == AF_INET)
            ((sockaddr_in*)rp->ai_addr)->sin_port = htons(port);
        else
            ((sockaddr_in6*)rp->ai_addr)->sin6_port = htons(port);
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);
    if (sockfd < 0) {
        out.notes.push_back("connect failed");
        return out;
    }
    set_socket_timeout(sockfd, timeout);
    if (port == 80 || port == 443) {
        if (port == 443) probe_https(sockfd, host, timeout, out);
        else {
            std::ostringstream req;
            req << "HEAD / HTTP/1.1\r\nHost: " << host << "\r\nUser-Agent: " << userAgent << "\r\n";
            std::string reqs = req.str();
            ssize_t sent = send(sockfd, reqs.c_str(), (int)reqs.size(), 0);
            if (sent < 0) {
                out.notes.push_back("HTTP send error: " + std::string(strerror(errno)));
                std::string data = recv_all(sockfd, timeout);
                out.banner = data;
            } else {
                std::string data = recv_all(sockfd, timeout);
                out.banner = data;
                parse_http_response(data, out.http_headers, out.notes);
            }
        }
    } else {
        std::string data = recv_all(sockfd, timeout);
        out.banner = data;
    }
    close(sockfd);
    out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
    return out;
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0]
                  << " target_host [--domains domains.txt] [--timeout 3.0] [--threads 8] [--json out.json]\n";
        return 1;
    }
    std::vector<std::string> hosts;
    std::string domains_file;
    double timeout = 3.0;
    size_t threads = 8;
    std::string json_out;
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--timeout" && i + 1 < argc) {
            timeout = std::stod(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::stoul(argv[++i]);
        } else if (arg == "--json" && i + 1 < argc) {
            json_out = argv[++i];
        } else if (arg == "--domains" && i + 1 < argc) {
            domains_file = argv[++i];
        } else if (arg[0] != '-') {
            hosts.push_back(arg); // Single domain
        }
    }
    // If we have a domains file, read it
    if (!domains_file.empty()) {
        std::ifstream file(domains_file);
        if (file.is_open()) {
            std::string domain;
            while (std::getline(file, domain)) {
                if (!domain.empty()) {
                    hosts.push_back(domain);
                }
            }
        } else {
            std::cerr << "Failed to open domains file: " << domains_file << std::endl;
            return 1;
        }
    }
    // Display the list of domains
    if (hosts.empty()) {
        std::cerr << "No domains provided.\n";
        return 1;
    }
    std::vector<std::pair<int, std::string>> ports;
    for (const auto& p : DEFAULT_PORTS)
        ports.push_back(p);
    std::mutex out_mutex;
    std::vector<ScanResult> results;
    std::queue<int> work;
    for (size_t i = 0; i < ports.size(); ++i)
        work.push((int)i);
    // Worker function for scanning domains
    auto worker = [&]() {
        while (true) {
            int idx = -1;
            {
                std::lock_guard<std::mutex> lock(out_mutex);
                if (work.empty())
                    return;
                idx = work.front();
                work.pop();
            }
            const auto& [port, service] = ports[idx];

            // Scan each domain
            for (const auto& host : hosts) {
                ScanResult r = probe_tcp_banner(host, port, timeout);
                {
                    std::lock_guard<std::mutex> lock(out_mutex);
                    results.push_back(std::move(r));
                }
            }
        }
    };

    // Create threads to process the scan
    std::vector<std::thread> pool;
    for (size_t i = 0; i < threads; ++i)
        pool.emplace_back(worker);

    // Join threads
    for (auto& t : pool)
        t.join();

    // Output the results
    for (const auto& r : results) {
        std::cout << "[" << r.host << ":" << r.port << "] ";
        if (!r.reachable) {
            std::cout << "unreachable\n";
            continue;
        }
        std::cout << "reachable (" << std::fixed << std::setprecision(2)
                  << r.duration_s << "s)\n";
        if (!r.banner.empty())
            std::cout << r.banner << "\n";
        for (const auto& n : r.notes)
            std::cout << "  - " << n << "\n";
        std::cout << "\n";
    }

    // Optionally output results to a JSON file
    if (!json_out.empty()) {
        std::ofstream jf(json_out);
        jf << "\n  \"results\": [\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            jf << "    {\n";
            jf << "      \"host\": \"" << r.host << "\",\n";
            jf << "      \"port\": " << r.port << ",\n";
            jf << "      \"reachable\": " << (r.reachable ? "true" : "false") << ",\n";
            jf << "      \"duration\": " << r.duration_s << ",\n";
            jf << "      \"banner\": \"" << r.banner << "\",\n";
            jf << "      \"headers\": {\n";
            size_t hc = 0;
            for (const auto& h : r.http_headers) {
                jf << "        \"" << h.first << "\": "
                   << std::quoted(h.second);
                if (++hc < r.http_headers.size()) jf << ",";
                jf << "\n";
            }
            jf << "      },\n";
            jf << "      \"notes\": [";
            for (size_t n = 0; n < r.notes.size(); ++n) {
                jf << std::quoted(r.notes[n]);
                if (n + 1 < r.notes.size()) jf << ", ";
            }
            jf << "]\n";
            jf << "    }";
            if (i + 1 < results.size()) jf << ",";
            jf << "\n";
        }
        jf << "  ]\n}\n";
    }

    return 0;
}#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <chrono>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <queue>
#include <fstream>
#include <iomanip>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
using namespace std::chrono;
// Default ports for common services
static const std::map<int, std::string> DEFAULT_PORTS = {
    {21, "ftp"},         // FTP
    {22, "ssh"},         // SSH
    {23, "telnet"},      // Telnet
    {25, "smtp"},        // SMTP
    {53, "dns"},         // DNS
    {80, "http"},        // HTTP
    {443, "https"},      // HTTPS
    {3306, "mysql"},     // MySQL
    {3309, "mysql (Cluster)"}, // MySQL Cluster
    {5432, "postgresql"}, // PostgreSQL
    {6379, "redis"},     // Redis
    {27017, "mongodb"},  // MongoDB
    {5984, "couchdb"},   // CouchDB
    {8080, "http-alt"},  // HTTP alternative (used by Tomcat, Nginx, etc.)
    {8443, "https-alt"}, // HTTPS alternative (used by some Tomcat configurations)
    {11211, "memcached"}, // Memcached
    {21, "ftp"},         // FTP
    {2222, "ssh-alt"},   // SSH alternative (used by some VPS and cloud providers)
    {5000, "flask"},     // Flask (default for web development)
    {6379, "redis"},     // Redis
    {9000, "php-fpm"},   // PHP-FPM
    {10000, "webmin"},   // Webmin
    {25565, "minecraft"} // Minecraft (gaming)
};
// Max bytes to read for banners
static const size_t BANNER_READ_BYTES = 4096;

// Struct to store scan result
struct ScanResult {
    std::string host;
    int port;
    std::string service_guess;
    bool reachable = false;
    std::string banner;
    std::map<std::string, std::string> http_headers;
    std::vector<std::string> notes;
    double duration_s = 0.0;
};

// Socket timeout setter
static bool set_socket_timeout(int sockfd, double seconds) {
    struct timeval tv;
    tv.tv_sec = static_cast<int>(seconds);
    tv.tv_usec = static_cast<int>((seconds - tv.tv_sec) * 1e6);
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
        return false;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return true;
}

// Function to receive banner and other data from socket
static std::string recv_all(int sockfd, double timeout, size_t max_bytes = BANNER_READ_BYTES) {
    set_socket_timeout(sockfd, timeout);
    std::string buffer;
    char tmp[2048];
    while (buffer.size() < max_bytes) {
        ssize_t n = recv(sockfd, tmp, sizeof(tmp), 0);
        if (n > 0) {
            buffer.append(tmp, n);
            if (buffer.find("\r\n\r\n") != std::string::npos) break;
        } else {
            break;
        }
    }
    return buffer;
}
static void parse_http_response(const std::string& data,
                                std::map<std::string, std::string>& headers,
                                std::vector<std::string>& notes) {
    std::istringstream ss(data);
    std::string line;
    if (!std::getline(ss, line)) return;

    if (!line.empty() && line.back() == '\r') line.pop_back();
    headers["status_line"] = line;

    std::istringstream sl(line);
    std::string httpver;
    int status = 0;
    std::string reason;
    if (sl >> httpver >> status) {
        std::getline(sl, reason);
        if (!reason.empty() && reason[0] == ' ') reason.erase(0, 1);
        headers["status_code"] = std::to_string(status);
        headers["reason"] = reason;
        if (status != 200) notes.push_back("HTTP non-200 status: " + std::to_string(status));
    } else {
        notes.push_back("Malformed HTTP status line");
        return;
    }

    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) break;
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        std::string key = line.substr(0, pos);
        std::string val = line.substr(pos + 1);
        size_t a = val.find_first_not_of(" \t");
        if (a != std::string::npos) val = val.substr(a);
        headers[key] = val;
    }
}
static void probe_https(int sockfd, const std::string& host, double timeout, ScanResult& out) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        out.notes.push_back("SSL_CTX_new failed");
        return;
    }
    const unsigned char alpn_protos[] = {2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    SSL_CTX_set_alpn_protos(ctx, alpn_protos, sizeof(alpn_protos));
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    SSL_set_tlsext_host_name(ssl, host.c_str());
    if (SSL_connect(ssl) != 1) {
        out.notes.push_back("TLS handshake failed");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return;
    }
    out.reachable = true;
    out.notes.push_back("TLS version: " + std::string(SSL_get_version(ssl)));
    const char* cipher = SSL_get_cipher(ssl);
    if (cipher) out.notes.push_back("Cipher: " + std::string(cipher));

    const unsigned char* proto = nullptr;
    unsigned int proto_len = 0;
    SSL_get0_alpn_selected(ssl, &proto, &proto_len);
    if (proto_len > 0)
        out.notes.push_back("ALPN protocol: " + std::string(reinterpret_cast<const char*>(proto), proto_len));

    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        char* subj = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        char* iss = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        if (subj) out.notes.push_back(std::string("TLS Subject: ") + subj);
        if (iss) out.notes.push_back(std::string("TLS Issuer: ") + iss);
        OPENSSL_free(subj);
        OPENSSL_free(iss);
        X509_free(cert);
    }

    std::ostringstream req;
    req << "HEAD / HTTP/1.1\r\nHost: " << host
        << "\r\nUser-Agent: banner-scanner/1.0\r\n\r\n";
    SSL_write(ssl, req.str().c_str(), req.str().size());
    char buf[2048];
    std::string data;
    int n;
    while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        data.append(buf, n);
        if (data.find("\r\n\r\n") != std::string::npos) break;
    }
    out.banner = data;
    parse_http_response(data, out.http_headers, out.notes);

    auto it = out.http_headers.find("Server");
    if (it != out.http_headers.end()) {
        std::string srv = it->second;
        if (srv.find("Apache") != std::string::npos) srv = "Apache";
        else if (srv.find("nginx") != std::string::npos) srv = "nginx";
        else if (srv.find("Microsoft-IIS") != std::string::npos) srv = "IIS";
        out.notes.push_back("Normalized server: " + srv);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}
static ScanResult probe_tcp_banner(const std::string& host, int port, double timeout) {
    std::string userAgent = "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.166 Safari/537.36\r\n\r\n";
    ScanResult out;
    out.host = host;
    out.port = port;
    out.service_guess = DEFAULT_PORTS.at(port);
    auto start = high_resolution_clock::now();
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return out;

    int sockfd = -1;
    for (auto rp = res; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) continue;
        if (rp->ai_family == AF_INET)
            ((sockaddr_in*)rp->ai_addr)->sin_port = htons(port);
        else
            ((sockaddr_in6*)rp->ai_addr)->sin6_port = htons(port);
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(res);
    if (sockfd < 0) {
        out.notes.push_back("connect failed");
        return out;
    }
    set_socket_timeout(sockfd, timeout);
    if (port == 80 || port == 443) {
        if (port == 443) probe_https(sockfd, host, timeout, out);
        else {
            std::ostringstream req;
            req << "HEAD / HTTP/1.1\r\nHost: " << host << "\r\nUser-Agent: " << userAgent << "\r\n";
            std::string reqs = req.str();
            ssize_t sent = send(sockfd, reqs.c_str(), (int)reqs.size(), 0);
            if (sent < 0) {
                out.notes.push_back("HTTP send error: " + std::string(strerror(errno)));
                std::string data = recv_all(sockfd, timeout);
                out.banner = data;
            } else {
                std::string data = recv_all(sockfd, timeout);
                out.banner = data;
                parse_http_response(data, out.http_headers, out.notes);
            }
        }
    } else {
        std::string data = recv_all(sockfd, timeout);
        out.banner = data;
    }
    close(sockfd);
    out.duration_s = duration<double>(high_resolution_clock::now() - start).count();
    return out;
}
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0]
                  << " target_host [--domains domains.txt] [--timeout 3.0] [--threads 8] [--json out.json]\n";
        return 1;
    }
    std::vector<std::string> hosts;
    std::string domains_file;
    double timeout = 3.0;
    size_t threads = 8;
    std::string json_out;
    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--timeout" && i + 1 < argc) {
            timeout = std::stod(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::stoul(argv[++i]);
        } else if (arg == "--json" && i + 1 < argc) {
            json_out = argv[++i];
        } else if (arg == "--domains" && i + 1 < argc) {
            domains_file = argv[++i];
        } else if (arg[0] != '-') {
            hosts.push_back(arg); // Single domain
        }
    }
    // If we have a domains file, read it
    if (!domains_file.empty()) {
        std::ifstream file(domains_file);
        if (file.is_open()) {
            std::string domain;
            while (std::getline(file, domain)) {
                if (!domain.empty()) {
                    hosts.push_back(domain);
                }
            }
        } else {
            std::cerr << "Failed to open domains file: " << domains_file << std::endl;
            return 1;
        }
    }
    // Display the list of domains
    if (hosts.empty()) {
        std::cerr << "No domains provided.\n";
        return 1;
    }
    std::vector<std::pair<int, std::string>> ports;
    for (const auto& p : DEFAULT_PORTS)
        ports.push_back(p);
    std::mutex out_mutex;
    std::vector<ScanResult> results;
    std::queue<int> work;
    for (size_t i = 0; i < ports.size(); ++i)
        work.push((int)i);
    // Worker function for scanning domains
    auto worker = [&]() {
        while (true) {
            int idx = -1;
            {
                std::lock_guard<std::mutex> lock(out_mutex);
                if (work.empty())
                    return;
                idx = work.front();
                work.pop();
            }
            const auto& [port, service] = ports[idx];

            // Scan each domain
            for (const auto& host : hosts) {
                ScanResult r = probe_tcp_banner(host, port, timeout);
                {
                    std::lock_guard<std::mutex> lock(out_mutex);
                    results.push_back(std::move(r));
                }
            }
        }
    };

    // Create threads to process the scan
    std::vector<std::thread> pool;
    for (size_t i = 0; i < threads; ++i)
        pool.emplace_back(worker);

    // Join threads
    for (auto& t : pool)
        t.join();

    // Output the results
    for (const auto& r : results) {
        std::cout << "[" << r.host << ":" << r.port << "] ";
        if (!r.reachable) {
            std::cout << "unreachable\n";
            continue;
        }
        std::cout << "reachable (" << std::fixed << std::setprecision(2)
                  << r.duration_s << "s)\n";
        if (!r.banner.empty())
            std::cout << r.banner << "\n";
        for (const auto& n : r.notes)
            std::cout << "  - " << n << "\n";
        std::cout << "\n";
    }

    // Optionally output results to a JSON file
    if (!json_out.empty()) {
        std::ofstream jf(json_out);
        jf << "\n  \"results\": [\n";
        for (size_t i = 0; i < results.size(); ++i) {
            const auto& r = results[i];
            jf << "    {\n";
            jf << "      \"host\": \"" << r.host << "\",\n";
            jf << "      \"port\": " << r.port << ",\n";
            jf << "      \"reachable\": " << (r.reachable ? "true" : "false") << ",\n";
            jf << "      \"duration\": " << r.duration_s << ",\n";
            jf << "      \"banner\": \"" << r.banner << "\",\n";
            jf << "      \"headers\": {\n";
            size_t hc = 0;
            for (const auto& h : r.http_headers) {
                jf << "        \"" << h.first << "\": "
                   << std::quoted(h.second);
                if (++hc < r.http_headers.size()) jf << ",";
                jf << "\n";
            }
            jf << "      },\n";
            jf << "      \"notes\": [";
            for (size_t n = 0; n < r.notes.size(); ++n) {
                jf << std::quoted(r.notes[n]);
                if (n + 1 < r.notes.size()) jf << ", ";
            }
            jf << "]\n";
            jf << "    }";
            if (i + 1 < results.size()) jf << ",";
            jf << "\n";
        }
        jf << "  ]\n}\n";
    }

    return 0;
}
