#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <iomanip>
#include <cstdlib>

// Boost Headers
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>

// OpenSSL Headers (Needed for extracting Cert Info)
#include <openssl/ssl.h>
#include <openssl/x509.h>

// Argument Parsing
#include <getopt.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using namespace std;

// Struct for storing URL information
struct URLInfo
{
    string scheme;
    string host;
    string port;
    string path;
};

// Simple URL Parser
URLInfo parse_url(const string &url)
{
    URLInfo info;
    string parsed = url;

    size_t scheme_end = parsed.find("://");
    if (scheme_end != string::npos)
    {
        info.scheme = parsed.substr(0, scheme_end);
        parsed = parsed.substr(scheme_end + 3);
    }
    else
    {
        info.scheme = "http";
    }

    size_t path_start = parsed.find("/");
    if (path_start != string::npos)
    {
        info.host = parsed.substr(0, path_start);
        info.path = parsed.substr(path_start);
    }
    else
    {
        info.host = parsed;
        info.path = "/";
    }

    size_t port_start = info.host.find(":");
    if (port_start != string::npos)
    {
        info.port = info.host.substr(port_start + 1);
        info.host = info.host.substr(0, port_start);
    }
    else
    {
        if (info.scheme == "https")
            info.port = "443";
        else
            info.port = "80";
    }
    return info;
}

// Get current timestamp
string get_timestamp()
{
    auto now = chrono::system_clock::now();
    auto in_time_t = chrono::system_clock::to_time_t(now);
    stringstream ss;
    ss << put_time(localtime(&in_time_t), "%Y-%m-%d %X");
    return ss.str();
}

// Extract and Print Cert Info using native OpenSSL handle
void print_cert_info(SSL *ssl)
{
    if (!ssl)
        return;
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        char *line;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        cout << "Subject: " << line << endl;
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        cout << "Issuer: " << line << endl;
        free(line);
        X509_free(cert);
    }
    else
    {
        cout << "No certificate info available." << endl;
    }
}

// --- Main Download Function ---

int main(int argc, char *argv[])
{
    string output_file = "";
    bool save_output = false;

    // 1. Argument Parsing
    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt_idx = 0;
    int c;
    while ((c = getopt_long(argc, argv, "o:h", long_options, &opt_idx)) != -1)
    {
        switch (c)
        {
        case 'o':
            output_file = optarg;
            save_output = true;
            break;
        case 'h':
            cout << "Usage: " << argv[0] << " [-o <file>] <url>" << endl;
            return 0;
        default:
            cerr << "Use -h for help." << endl;
            return 1;
        }
    }

    if (optind >= argc)
    {
        cerr << "Error: Missing URL argument." << endl;
        return 1;
    }

    string original_url = argv[optind];
    string current_url = original_url;
    long long total_body_size = 0;
    int redirect_count = 0;
    const int MAX_REDIRECTS = 10;

    // Start Timing
    auto start_time = chrono::high_resolution_clock::now();

    // 2. IO Context and SSL Context
    net::io_context ioc;
    ssl::context ctx(ssl::context::tlsv12_client);
    ctx.set_default_verify_paths();
    // Use relaxed verification for the assignment context unless strictness is required
    ctx.set_verify_mode(ssl::verify_none);

    while (redirect_count < MAX_REDIRECTS)
    {
        URLInfo url = parse_url(current_url);
        bool is_https = (url.scheme == "https");

        // 3. Resolve Host
        tcp::resolver resolver(ioc);
        auto const results = resolver.resolve(url.host, url.port);

        // 4. Set up the Request
        http::request<http::string_body> req{http::verb::get, url.path, 11};
        req.set(http::field::host, url.host);
        req.set(http::field::user_agent, "myCurl-Boost/1.0");

        // Response object
        http::response<http::string_body> res;

        try
        {
            if (is_https)
            {
                beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

                // Set SNI Hostname
                if (!SSL_set_tlsext_host_name(stream.native_handle(), url.host.c_str()))
                {
                    beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
                    throw beast::system_error{ec};
                }

                get_lowest_layer(stream).connect(results);
                stream.handshake(ssl::stream_base::client);

                // Print Cert Info
                print_cert_info(stream.native_handle());

                http::write(stream, req);
                beast::flat_buffer buffer;
                http::read(stream, buffer, res);

                beast::error_code ec;
                stream.shutdown(ec);
                if (ec == net::error::eof)
                    ec = {}; // Rationale: https://stackoverflow.com/questions/25587403/boost-asio-ssl-async-shutdown-always-finishes-with-an-error
            }
            else
            {
                beast::tcp_stream stream(ioc);
                stream.connect(results);

                http::write(stream, req);
                beast::flat_buffer buffer;
                http::read(stream, buffer, res);

                beast::error_code ec;
                stream.socket().shutdown(tcp::socket::shutdown_both, ec);
            }
        }
        catch (std::exception const &e)
        {
            cerr << "Error: " << e.what() << endl;
            return 1;
        }

        // 5. Handle Response Headers & Redirects
        cout << res.base() << endl; // Print Headers to STDOUT

        int status = res.result_int();
        if (status >= 300 && status < 400)
        {
            auto loc = res.find(http::field::location);
            if (loc != res.end())
            {
                string new_loc = string(loc->value());
                cout << "Redirecting to: " << new_loc << endl;
                current_url = new_loc;
                redirect_count++;
                continue;
            }
        }

        // 6. Save Body if final
        total_body_size = res.body().size();
        if (save_output)
        {
            ofstream outfile(output_file, ios::binary);
            outfile << res.body();
            outfile.close();
        }
        break; // Done
    }

    auto end_time = chrono::high_resolution_clock::now();
    chrono::duration<double> diff = end_time - start_time;
    double seconds = diff.count();

    // Calculate Mbps
    double mbps = 0.0;
    if (seconds > 0)
    {
        mbps = (total_body_size * 8.0) / 1000000.0 / seconds;
    }

    // Final Statistics Line
    cout << get_timestamp() << " "
         << original_url << " "
         << total_body_size << " [bytes] "
         << fixed << setprecision(6) << seconds << " [s] "
         << mbps << " [Mbps]" << endl;

    return 0;
}