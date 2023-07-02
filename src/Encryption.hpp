
#ifndef ENCRYPTION_HPP
#define ENCRYPTION_HPP

#include "HelperSources/Helper.hpp"
#include <cstdio>
#include <stdexcept>
#include <vector>
#include <optional>
#include <iostream>
#include <array>
#include <sodium.h>
#include "wifibroadcast-spdlog.h"

// Single Header file that can be used to add encryption to a lossy unidirectional link
// Other than encryption, (which might not seem important to the average user) this also adds packet validation, e.g. makes it impossible
// to receive data from a non-OpenHD wlan device

// For developing or when encryption is not important, you can use this default seed to
// create deterministic rx and tx keys
static const std::array<unsigned char, crypto_box_SEEDBYTES> DEFAULT_ENCRYPTION_SEED = {0};

class Encryptor {
 public:
  // enable a default deterministic encryption key by using std::nullopt
  // else, pass path to file with encryption keys
  explicit Encryptor(std::optional<std::string> keypair, const bool DISABLE_ENCRYPTION_FOR_PERFORMANCE = false)
      : DISABLE_ENCRYPTION_FOR_PERFORMANCE(DISABLE_ENCRYPTION_FOR_PERFORMANCE) {
    if (keypair == std::nullopt) {
      // use default encryption keys
      crypto_box_seed_keypair(rx_publickey.data(), tx_secretkey.data(), DEFAULT_ENCRYPTION_SEED.data());
      wifibroadcast::log::get_default()->debug("Using default keys");
    } else {
      FILE *fp;
      if ((fp = fopen(keypair->c_str(), "r")) == nullptr) {
        throw std::runtime_error(fmt::format("Unable to open {}: {}", keypair->c_str(), strerror(errno)));
      }
      if (fread(tx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read tx secret key: {}", strerror(errno)));
      }
      if (fread(rx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read rx public key: {}", strerror(errno)));
      }
      fclose(fp);
    }
  }
  // Don't forget to send the session key after creating a new one !
  void makeNewSessionKey(std::array<uint8_t, crypto_box_NONCEBYTES> &sessionKeyNonce,
                         std::array<uint8_t,
                                    crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> &sessionKeyData) {
    randombytes_buf(session_key.data(), sizeof(session_key));
    randombytes_buf(sessionKeyNonce.data(), sizeof(sessionKeyNonce));
    if (crypto_box_easy(sessionKeyData.data(), session_key.data(), sizeof(session_key),
                        sessionKeyNonce.data(), rx_publickey.data(), tx_secretkey.data()) != 0) {
      throw std::runtime_error("Unable to make session key!");
    }
  }
  int encrypt2(const uint64_t nonce,const uint8_t *src,std::size_t src_len,uint8_t* dest){
    long long unsigned int ciphertext_len;
    crypto_aead_chacha20poly1305_encrypt(dest, &ciphertext_len,
                                         src, src_len,
                                         (uint8_t *)nullptr, 0,
                                         nullptr,
                                         (uint8_t *) &nonce, session_key.data());
    return (int)ciphertext_len;
  }
  std::shared_ptr<std::vector<uint8_t>> encrypt3(const uint64_t nonce,const uint8_t *src,std::size_t src_len){
    auto ret=std::make_shared<std::vector<uint8_t>>(src_len + crypto_aead_chacha20poly1305_ABYTES);
    const auto size=encrypt2(nonce,src,src_len,ret->data());
    assert(size==ret->size());
    return ret;
  }
 private:
  // tx->rx keypair
  std::array<uint8_t, crypto_box_SECRETKEYBYTES> tx_secretkey{};
  std::array<uint8_t, crypto_box_PUBLICKEYBYTES> rx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
  // use this one if you are worried about CPU usage when using encryption
  const bool DISABLE_ENCRYPTION_FOR_PERFORMANCE;
};

class Decryptor {
 public:
  // enable a default deterministic encryption key by using std::nullopt
  // else, pass path to file with encryption keys
  explicit Decryptor(std::optional<std::string> keypair, const bool DISABLE_ENCRYPTION_FOR_PERFORMANCE = false)
      : DISABLE_ENCRYPTION_FOR_PERFORMANCE(DISABLE_ENCRYPTION_FOR_PERFORMANCE) {
    if (keypair == std::nullopt) {
      crypto_box_seed_keypair(tx_publickey.data(), rx_secretkey.data(), DEFAULT_ENCRYPTION_SEED.data());
      wifibroadcast::log::get_default()->debug("Using default keys");
    } else {
      FILE *fp;
      if ((fp = fopen(keypair->c_str(), "r")) == nullptr) {
        throw std::runtime_error(fmt::format("Unable to open {}: {}", keypair->c_str(), strerror(errno)));
      }
      if (fread(rx_secretkey.data(), crypto_box_SECRETKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read rx secret key: {}", strerror(errno)));
      }
      if (fread(tx_publickey.data(), crypto_box_PUBLICKEYBYTES, 1, fp) != 1) {
        fclose(fp);
        throw std::runtime_error(fmt::format("Unable to read tx public key: {}", strerror(errno)));
      }
      fclose(fp);
    }
    memset(session_key.data(), 0, sizeof(session_key));
  }
 private:
  // use this one if you are worried about CPU usage when using encryption
  const bool DISABLE_ENCRYPTION_FOR_PERFORMANCE;
 public:
  std::array<uint8_t, crypto_box_SECRETKEYBYTES> rx_secretkey{};
 public:
  std::array<uint8_t, crypto_box_PUBLICKEYBYTES> tx_publickey{};
  std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES> session_key{};
 public:
  // return true if a new session was detected (The same session key can be sent multiple times by the tx)
  bool onNewPacketSessionKeyData(const std::array<uint8_t, crypto_box_NONCEBYTES> &sessionKeyNonce,
                                 const std::array<uint8_t,crypto_aead_chacha20poly1305_KEYBYTES+ crypto_box_MACBYTES> &sessionKeyData) {
    std::array<uint8_t, sizeof(session_key)> new_session_key{};
    if (crypto_box_open_easy(new_session_key.data(),
                             sessionKeyData.data(), sessionKeyData.size(),
                             sessionKeyNonce.data(),
                             tx_publickey.data(), rx_secretkey.data()) != 0) {
      // this basically should just never happen, and is an error
      wifibroadcast::log::get_default()->warn("unable to decrypt session key");
      return false;
    }
    if (memcmp(session_key.data(), new_session_key.data(), sizeof(session_key)) != 0) {
      // this is NOT an error, the same session key is sent multiple times !
      wifibroadcast::log::get_default()->info("Decryptor-New session detected");
      session_key = new_session_key;
      return true;
    }
    return false;
  }

  int decrypt2(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size,uint8_t* dest){
    unsigned long long mlen;
    int res=crypto_aead_chacha20poly1305_decrypt(dest, &mlen,
                                                   nullptr,
                                                   encrypted, encrypted_size,
                                                   nullptr,0,
                                                   (uint8_t *) (&nonce), session_key.data());
    return res;
  }
  std::shared_ptr<std::vector<uint8_t>> decrypt3(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size){
    auto ret=std::make_shared<std::vector<uint8_t>>(encrypted_size - crypto_aead_chacha20poly1305_ABYTES);
    int res= decrypt2(nonce,encrypted,encrypted_size,ret->data());
    //assert(res==ret->size());
    return ret;
  }
};

#endif //ENCRYPTION_HPP