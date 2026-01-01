#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/time.h>
#include <iostream>

// Boost Headers
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/ssl.hpp>

// OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
using namespace std;

// --- Helper: Parse URL into Host, Port, and Path ---
void parse_url(const string &url, string &Desthost, string &Destport, string &Path, bool &Is_https)
{
    string purl = url;
    Is_https = false;

    // Check scheme
    size_t scheme_end = purl.find("://");
    if (scheme_end != string::npos)
    {
        string scheme = purl.substr(0, scheme_end);
        if (scheme == "https")
            Is_https = true;
        purl = purl.substr(scheme_end + 3);
    }

    // Check path
    size_t path_start = purl.find("/");
    if (path_start != string::npos)
    {
        Desthost = purl.substr(0, path_start);
        Path = purl.substr(path_start);
    }
    else
    {
        Desthost = purl;
        Path = "/";
    }

    // Check port
    size_t port_start = Desthost.find(":");
    if (port_start != string::npos)
    {
        Destport = Desthost.substr(port_start + 1);
        Desthost = Desthost.substr(0, port_start);
    }
    else
    {
        Destport = Is_https ? "443" : "80";
    }
}

// --- Helper: Get timestamp string (YYYY-MM-DD HH:MM:SS) ---
string get_timestamp()
{
    time_t now = time(NULL);
    struct tm buf;
    localtime_r(&now, &buf);
    char str[32];
    strftime(str, sizeof(str), "%Y-%m-%d %H:%M:%S", &buf);
    return string(str);
}

// --- Helper: Print Certificate Info ---
void print_cert_info(SSL *ssl)
{
    if (!ssl)
        return;
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert)
    {
        char *line;
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
    {
        printf("No certificate info available.\n");
    }
}

int main(int argc, char *argv[])
{
    char *Filename = NULL;
    bool Save_output = false;

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
            Filename = optarg;
            Save_output = true;
            break;
        case 'h':
            printf("Usage: %s [-o <file>] <url>\n", argv[0]);
            return 0;
        default:
            fprintf(stderr, "Use -h for help.\n");
            return 1;
        }
    }

    // Check if URL is provided
    if (optind >= argc)
    {
        fprintf(stderr, "Error: Missing URL argument.\n");
        return 1;
    }

    string Original_url = argv[optind];
    string Current_url = Original_url;
    long long Total_body_size = 0;
    int Redirect_count = 0;
    const int MAX_REDIRECTS = 10;

    // 2. Start Timing
    struct timeval start_tv, end_tv;
    gettimeofday(&start_tv, NULL);

    // Setup I/O context and SSL context
    net::io_context ioc;
    ssl::context ctx(ssl::context::tlsv12_client);
    ctx.set_default_verify_paths();
    ctx.set_verify_mode(ssl::verify_none);

    while (Redirect_count < MAX_REDIRECTS)
    {
        string Desthost, Destport, Path;
        bool Is_https;
        parse_url(Current_url, Desthost, Destport, Path, Is_https);

        try
        {
            // Resolve Host
            tcp::resolver resolver(ioc);
            auto const results = resolver.resolve(Desthost, Destport);

            // Prepare Request
            http::request<http::string_body> req{http::verb::get, Path, 11};
            req.set(http::field::host, Desthost);
            req.set(http::field::user_agent, "myCurl-Boost/1.0");

            http::response<http::string_body> res;

            // Handle HTTPS vs HTTP
            if (Is_https)
            {
                beast::ssl_stream<beast::tcp_stream> stream(ioc, ctx);

                // Set SNI Hostname (critical for virtual hosting)
                if (!SSL_set_tlsext_host_name(stream.native_handle(), Desthost.c_str()))
                {
                    beast::error_code ec{static_cast<int>(::ERR_get_error()), net::error::get_ssl_category()};
                    throw beast::system_error{ec};
                }

                get_lowest_layer(stream).connect(results);
                stream.handshake(ssl::stream_base::client);

                // Show Server Certificate
                print_cert_info(stream.native_handle());

                http::write(stream, req);
                beast::flat_buffer buffer;
                http::read(stream, buffer, res);

                beast::error_code ec;
                stream.shutdown(ec);
                if (ec == net::error::eof)
                    ec = {};
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

            // Show Response Headers
            cout << res.base() << endl;

            int status = res.result_int();

            // Handle Redirects (3xx)
            if (status >= 300 && status < 400)
            {
                auto loc = res.find(http::field::location);
                if (loc != res.end())
                {
                    string new_loc = string(loc->value());
                    printf("Redirecting to: %s\n", new_loc.c_str());
                    Current_url = new_loc;
                    Redirect_count++;
                    continue; // Loop again with new URL
                }
            }

            // Success - Process Body
            Total_body_size = res.body().size();

            // Show Body Size explicitly (before summary)
            printf("Body size: %lld bytes\n", Total_body_size);

            if (Save_output && Filename)
            {
                FILE *fp = fopen(Filename, "wb");
                if (fp)
                {
                    fwrite(res.body().c_str(), 1, res.body().size(), fp);
                    fclose(fp);
                }
                else
                {
                    perror("fopen");
                }
            }
            // Break loop on successful non-redirect response
            break;
        }
        catch (std::exception const &e)
        {
            fprintf(stderr, "Error: %s\n", e.what());
            return 1;
        }
    }

    // 3. Stop Timing
    gettimeofday(&end_tv, NULL);
    double seconds = (end_tv.tv_sec - start_tv.tv_sec) +
                     (end_tv.tv_usec - start_tv.tv_usec) / 1000000.0;

    // 4. Calculate Speed
    double mbps = 0.0;
    if (seconds > 0)
    {
        mbps = (Total_body_size * 8.0) / 1000000.0 / seconds;
    }

    // 5. Final Summary Line
    printf("%s %s %lld [bytes] %.6f [s] %.6f [Mbps]\n",
           get_timestamp().c_str(),
           Original_url.c_str(),
           Total_body_size,
           seconds,
           mbps);

    return 0;
}