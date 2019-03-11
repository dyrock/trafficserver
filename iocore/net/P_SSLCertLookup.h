/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include <openssl/ssl.h>

#include "ProxyConfig.h"

struct SSLConfigParams;
struct SSLContextStorage;

struct ssl_ticket_key_t {
  unsigned char key_name[16];
  unsigned char hmac_secret[16];
  unsigned char aes_key[16];
};

struct ssl_ticket_key_block {
  unsigned num_keys;
  ssl_ticket_key_t keys[];
};
/** A certificate context.

    This holds data about a certificate and how it is used by the SSL logic. Current this is mainly
    the openSSL certificate and an optional action, which in turn is limited to just tunneling.

    Instances are passed around and returned when matching connections to certificates.

    Instances of this class are stored on a list and then referenced via index in that list so that
    there is exactly one place we can find all the @c SSL_CTX instances exactly once.

*/
struct SSLCertContext {
private:
  mutable std::mutex ctx_mutex;
  shared_SSL_CTX ctx;

public:
  SSLCertContext() : ctx_mutex(), ctx(nullptr), opt(SSLCertContextOption::OPT_NONE), userconfig(nullptr), keyblock(nullptr) {}
  explicit SSLCertContext(SSL_CTX *c)
    : ctx_mutex(), ctx(c, SSL_CTX_free), opt(SSLCertContextOption::OPT_NONE), userconfig(nullptr), keyblock(nullptr)
  {
  }
  SSLCertContext(shared_SSL_CTX sc, SSLCertContextOption o) : ctx_mutex(), ctx(sc), opt(o), userconfig(nullptr), keyblock(nullptr)
  {
  }
  SSLCertContext(shared_SSL_CTX sc, SSLCertContextOption o, shared_ssl_user_config u)
    : ctx_mutex(), ctx(sc), opt(o), userconfig(u), keyblock(nullptr)
  {
  }
  SSLCertContext(shared_SSL_CTX sc, SSLCertContextOption o, shared_ssl_user_config u, ssl_ticket_key_block *kb)
    : ctx_mutex(), ctx(sc), opt(o), userconfig(u), keyblock(kb)
  {
  }
  SSLCertContext(SSLCertContext const &other);
  SSLCertContext &operator=(SSLCertContext const &other);

  shared_SSL_CTX getCtx();
  void setCtx(shared_SSL_CTX sc);
  void release();

  SSLCertContextOption opt;          ///< Special handling option.
  shared_ssl_user_config userconfig; ///< User provided settings
  ssl_ticket_key_block *keyblock;    ///< session keys associated with this address
};

struct SSLCertLookup : public ConfigInfo {
  SSLContextStorage *ssl_storage;
  shared_SSL_CTX ssl_default;
  bool is_valid;

  int insert(const char *name, SSLCertContext const &cc);
  int insert(const IpEndpoint &address, SSLCertContext const &cc);

  /** Find certificate context by IP address.
      The IP addresses are taken from the socket @a s.
      Exact matches have priority, then wildcards. The destination address is preferred to the source address.
      @return @c A pointer to the matched context, @c nullptr if no match is found.
  */
  SSLCertContext *find(const IpEndpoint &address) const;

  /** Find certificate context by name (FQDN).
      Exact matches have priority, then wildcards. Only destination based matches are checked.
      @return @c A pointer to the matched context, @c nullptr if no match is found.
  */
  SSLCertContext *find(const char *name) const;

  // Return the last-resort default TLS context if there is no name or address match.
  SSL_CTX *
  defaultContext() const
  {
    return ssl_default.get();
  }

  unsigned count() const;
  SSLCertContext *get(unsigned i) const;

  SSLCertLookup();
  ~SSLCertLookup() override;
};

void ticket_block_free(void *ptr);
ssl_ticket_key_block *ticket_block_alloc(unsigned count);
ssl_ticket_key_block *ticket_block_create(char *ticket_key_data, int ticket_key_len);
ssl_ticket_key_block *ssl_create_ticket_keyblock(const char *ticket_key_path);
