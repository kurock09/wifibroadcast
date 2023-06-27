//
// Created by consti10 on 27.06.23.
//

#ifndef WIFIBROADCAST_TXRXINSTANCE_H
#define WIFIBROADCAST_TXRXINSTANCE_H

#include <atomic>

#include "Encryption.hpp"
#include "RadiotapHeader.hpp"
#include "RawTransmitter.hpp"
#include "wifibroadcast.hpp"

/**
 * Wraps one or more wifi card in monitor mode
 * Provides easy interface to inject data packets and register callbacks to process received data packets
 * Adds packet encryption and authentication via libsodium (can be disabled for performance)
 * Quick usage description by example:
 * System 1: card 1
 * System 2: card 2
 * air in between card 1 and card 2
 * Create an instance of  TxRxInstance on system 1 and system 2
 * inject packets using TxRxInstance on system 1 -> receive them using TxRxInstance on system 2
 * inject packets using TxRxInstance on system 2 -> receive them using TxRxInstance on system 1
 */
class TxRxInstance {
 public:
  explicit TxRxInstance(std::vector<std::string> wifi_cards);
  /**
   * Creates a valid injection packet which has the layout:
   * radiotap_header,ieee_80211_header,nonce (64 bit), encrypted data, encryption prefix
   * A increasing nonce is used for each packet, and is used for packet validation
   * on the receiving side.
   * @param radioPort used to multiplex more than one data stream, the radio port is written into the IEE80211 header
   * @param data the packet payload
   * @param data_len the packet payload length
   */
  void tx_inject_packet(uint8_t radioPort,const uint8_t* data,int data_len);

  // register a callback that is called every time a valid packet (for the given radio port) is received
  void rx_register_callback(const uint8_t radioPort,void* data){

  }

  void start_receiving();

 private:
  void announce_session_key_if_needed();
  void send_session_key();;

  void loop_receive_packets();
  int loop_iter(int rx_index);

  void on_new_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  void process_received_data_packet(int wlan_idx,uint8_t radio_port,const uint8_t *pkt_payload,size_t pkt_payload_size);

  void on_valid_packet(int wlan_index,uint8_t radio_port,std::shared_ptr<std::vector<uint8_t>> data);
 private:
  std::shared_ptr<spdlog::logger> m_console;
  std::vector<std::string> m_wifi_cards;
  std::chrono::steady_clock::time_point m_session_key_announce_ts{};
  RadiotapHeader m_radiotap_header;
  Ieee80211Header mIeee80211Header{};
  uint16_t m_ieee80211_seq = 0;
  uint64_t m_nonce=0;
  int m_highest_rssi_index=0;
  // Session key used for sending data
  WBSessionKeyPacket m_tx_sess_key_packet;
 private:
  std::unique_ptr<Encryptor> m_encryptor;
  std::unique_ptr<Decryptor> m_decryptor;
 private:
  struct PcapTxRx{
    pcap_t *tx= nullptr;
    pcap_t *rx= nullptr;
  };
  std::vector<PcapTxRx> m_pcap_handles;
 private:
  bool keep_running= true;
  int m_n_receiver_errors=0;
  std::unique_ptr<std::thread> m_receive_thread;
  std::vector<pollfd> mReceiverFDs;
  std::chrono::steady_clock::time_point m_last_receiver_error_log=std::chrono::steady_clock::now();
  static constexpr auto RADIO_PORT_SESSION_KEY_PACKETS=25;
};

#endif  // WIFIBROADCAST_TXRXINSTANCE_H
