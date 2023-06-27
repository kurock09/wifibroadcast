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
#include "SeqNrHelper.hpp"

/**
 * Wraps one or more wifi card in monitor mode
 * Provides easy interface to inject data packets and register a callback to process received data packets
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

  /**
   * Callback that is called every time a valid packet has been received
   * (valid = has been validated and decrypted)
   * @param nonce: the nonce of the received packet (can be used for sequence numbering)
   * @param wlan_index: the card on which the packet was received (in case there are multiple cards used for wb)
   * @param radio_port: the multiplex index used to seperate streams during injection
   */
  typedef std::function<void(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len)> OUTPUT_DATA_CALLBACK;
  void rx_register_callback(OUTPUT_DATA_CALLBACK cb);

  /**
   * Receiving packets happens in the background in another thread.
   */
  void start_receiving();
 private:
  void announce_session_key_if_needed();
  void send_session_key();;

  void loop_receive_packets();
  int loop_iter(int rx_index);

  void on_new_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  void process_received_data_packet(int wlan_idx,uint8_t radio_port,const uint8_t *pkt_payload,size_t pkt_payload_size);

  void on_valid_packet(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len);
 private:
  std::shared_ptr<spdlog::logger> m_console;
  std::vector<std::string> m_wifi_cards;
  std::chrono::steady_clock::time_point m_session_key_announce_ts{};
  RadiotapHeader m_radiotap_header;
  Ieee80211Header mIeee80211Header{};
  const bool advanced_debugging= false;
  uint16_t m_ieee80211_seq = 0;
  //uint64_t m_nonce=0;
  uint16_t m_nonce=0;
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
  // for calculating the packet loss on the rx side
  seq_nr::Helper m_seq_nr_helper;
  OUTPUT_DATA_CALLBACK m_output_cb= nullptr;
 private:
  // Receiving packet statistics
  struct RxPacketStatsPerCard{
    // total number of received packets (can come from non-wb, too)
    uint64_t count_received_packets=0;
    // total number of successfully validated & decrypted packets
    uint64_t count_valid_packets=0;
  };
  std::vector<RxPacketStatsPerCard> m_rx_packet_stats;
};

#endif  // WIFIBROADCAST_TXRXINSTANCE_H
