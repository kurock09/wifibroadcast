
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

// Single Header file that can be used to add encryption+packet validation
// (Or packet validation only to save CPU resources)
// to a lossy unidirectional link
// Packet validation is quite important, to make sure only openhd packets (and not standard wifi packets) are used in OpenHD

// For developing or when encryption is not important, you can use this default seed to
// create deterministic rx and tx keys
static const std::array<unsigned char, crypto_box_SEEDBYTES> DEFAULT_ENCRYPTION_SEED = {0};

static_assert(crypto_onetimeauth_BYTES==crypto_aead_chacha20poly1305_ABYTES);
// Encryption (or packet validation) adds this many bytes to the end of the message
static constexpr auto ENCRYPTION_ADDITIONAL_VALIDATION_DATA=crypto_aead_chacha20poly1305_ABYTES;

class Encryptor {
 public:
  /**
   *
   * @param keypair encryption key, otherwise enable a default deterministic encryption key by using std::nullopt
   * @param DISABLE_ENCRYPTION_FOR_PERFORMANCE only validate, do not encrypt (less CPU usage)
   */
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
  /**
   * Encrypt the given message of size @param src_len
   * (Or if encryption is enable, only calculate the message sign)
   * and write the (encrypted) data and validation data into dest.
   * Returns written data size (msg payload plus sign data)
   */
  int encrypt2(const uint64_t nonce,const uint8_t *src,std::size_t src_len,uint8_t* dest){
    if(DISABLE_ENCRYPTION_FOR_PERFORMANCE){
      memcpy(dest,src, src_len);
      uint8_t* sign=dest+src_len;
      crypto_onetimeauth(sign,src,src_len,session_key.data());
      return src_len+crypto_onetimeauth_BYTES;
    }
    long long unsigned int ciphertext_len;
    crypto_aead_chacha20poly1305_encrypt(dest, &ciphertext_len,
                                         src, src_len,
                                         (uint8_t *)nullptr, 0,
                                         nullptr,
                                         (uint8_t *) &nonce, session_key.data());
    return (int)ciphertext_len;
  }
  // For easy use - returns a buffer including (encrypted) payload plus validation data
  std::shared_ptr<std::vector<uint8_t>> encrypt3(const uint64_t nonce,const uint8_t *src,std::size_t src_len){
    auto ret=std::make_shared<std::vector<uint8_t>>(src_len + ENCRYPTION_ADDITIONAL_VALIDATION_DATA);
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
  //static_assert(crypto_onetimeauth_BYTES);
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
  /**
   * Decrypt (or validate only if encryption is disabled) the given message
   * and writes the original message content into dest.
   * Returns true on success, false otherwise (false== the message is not a valid message)
   */
  bool decrypt2(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size,uint8_t* dest){
    if(DISABLE_ENCRYPTION_FOR_PERFORMANCE){
      const auto payload_size=encrypted_size-crypto_onetimeauth_BYTES;
      assert(payload_size>0);
      const uint8_t* sign=encrypted+payload_size;
      //const int res=crypto_auth_hmacsha256_verify(sign,msg,payload_size,session_key.data());
      const int res=crypto_onetimeauth_verify(sign,encrypted,payload_size,session_key.data());
      if(res!=-1){
        memcpy(dest,encrypted,payload_size);
        return true;
      }
      return false;
    }
    unsigned long long mlen;
    int res=crypto_aead_chacha20poly1305_decrypt(dest, &mlen,
                                                   nullptr,
                                                   encrypted, encrypted_size,
                                                   nullptr,0,
                                                   (uint8_t *) (&nonce), session_key.data());
    return res!=-1;
  }
  std::shared_ptr<std::vector<uint8_t>> decrypt3(const uint64_t& nonce,const uint8_t* encrypted,int encrypted_size){
    auto ret=std::make_shared<std::vector<uint8_t>>(encrypted_size - get_additional_payload_size());
    const auto res= decrypt2(nonce,encrypted,encrypted_size,ret->data());
    if(res){
      return ret;
    }
    return nullptr;
  }
  int get_additional_payload_size() const{
    if(DISABLE_ENCRYPTION_FOR_PERFORMANCE){
      return crypto_onetimeauth_BYTES;
    }
    return crypto_aead_chacha20poly1305_ABYTES;
  }
};

#endif //ENCRYPTION_HPP