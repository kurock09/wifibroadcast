//
// Created by consti10 on 27.06.23.
//

#ifndef WIFIBROADCAST_TXRXINSTANCE_H
#define WIFIBROADCAST_TXRXINSTANCE_H

#include <atomic>
#include <map>

#include "Encryption.hpp"
#include "RadiotapHeader.hpp"
#include "RawTransmitter.hpp"
#include "SeqNrHelper.hpp"
#include "WBReceiverStats.hpp"
#include "wifibroadcast.hpp"

/**
 * Wraps one or more wifi card in monitor mode
 * Provides easy interface to inject data packets and register a callback to
 * process received data packets Adds packet encryption and authentication via
 * libsodium (can be disabled for performance) Allows multiplexing of multiple
 * data streams (radio_port) Quick usage description by example: System 1: card
 * 1 System 2: card 2 air in between card 1 and card 2 Create an instance of
 * TxRxInstance on system 1 and system 2 inject packets using TxRxInstance on
 * system 1 -> receive them using TxRxInstance on system 2 inject packets using
 * TxRxInstance on system 2 -> receive them using TxRxInstance on system 1
 */
class TxRxInstance {
 public:
  struct Options{
    // dirty, rssi on rtl8812au is "bugged", this discards the first rssi value reported by the card.
    bool rtl8812au_rssi_fixup=false;
  };
  explicit TxRxInstance(std::vector<std::string> wifi_cards,Options options1);
  TxRxInstance(const TxRxInstance &) = delete;
  TxRxInstance &operator=(const TxRxInstance &) = delete;
  ~TxRxInstance();
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
   * @param radio_port: the multiplex index used to separate streams during injection
   */
  typedef std::function<void(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len)> OUTPUT_DATA_CALLBACK;
  typedef std::function<void(uint64_t nonce,int wlan_index,const uint8_t *data, const std::size_t data_len)> SPECIFIC_OUTPUT_DATA_CB;
  // register callback that is called each time a valid packet is received (any multiplexed stream)
  void rx_register_callback(OUTPUT_DATA_CALLBACK cb);
  // register callback that is called each time a valid packet is received for a specific stream
  void rx_register_specific_cb(uint8_t radioPort,SPECIFIC_OUTPUT_DATA_CB cb);

  /**
   * Receiving packets happens in the background in another thread.
   */
  void start_receiving();
  void stop_receiving();

  /**
   * Really verbose logs (warning: Spams console)
   */
   void set_extended_debugging(bool enable_debug_tx,bool enable_debug_rx);

   // These are for updating injection parameters at run time. They will be applied on the next injected packet.
   // They are generally thread-safe. See RadiotapHeader for more information on what these parameters do.
   void tx_update_mcs_index(uint8_t mcs_index);
   void tx_update_channel_width(int width_mhz);
   void tx_update_stbc(int stbc);
   void tx_update_guard_interval(bool short_gi);
   void tx_update_ldpc(bool ldpc);

   // Statistics
   struct TxStats{
     int64_t n_injected_packets;
     int64_t n_injected_bytes;
     /*
     // calculated in 1 second intervals
     uint64_t current_bits_per_second;
     // Other than bits per second, packets per second is also an important metric -
     // Sending a lot of small packets for example should be avoided)
     uint64_t current_packets_per_second;*/
     // tx errors, first sign the tx can't keep up with the provided bitrate
     uint64_t count_tx_injections_error_hint;
   };
   struct RxStats{
     // Total count of received packets - can be from another wb tx, but also from someone else using wifi
     int64_t count_p_any=0;
     // Total count of valid received packets (decrypted)
     int64_t count_p_valid=0;
     // mcs index on the most recent okay data packet, if the card supports reporting it
     int last_received_packet_mcs_index=-1;
     // channel width (20Mhz or 40Mhz) on the most recent received okay data packet, if the card supports reporting it
     int last_received_packet_channel_width=-1;
   };
   struct RxStatsPerCard{
     RSSIForWifiCard rssi_for_wifi_card{};
     int64_t count_p_any=0;
     int64_t count_p_valid=0;
   };
   RxStats get_rx_stats();
   RxStatsPerCard get_rx_stats_for_card(int card_index);
 private:
  const Options m_options;
  std::shared_ptr<spdlog::logger> m_console;
  std::vector<std::string> m_wifi_cards;
  std::chrono::steady_clock::time_point m_session_key_announce_ts{};
  RadiotapHeader::UserSelectableParams m_radioTapHeaderParams{};
  RadiotapHeader m_radiotap_header;
  Ieee80211Header mIeee80211Header{};
  bool m_advanced_debugging_rx = false;
  bool m_advanced_debugging_tx = false;
  uint16_t m_ieee80211_seq = 0;
  uint64_t m_nonce=0;
  int m_highest_rssi_index=0;
  // Session key used for encrypting outgoing packets
  WBSessionKeyPacket m_tx_sess_key_packet;
  std::unique_ptr<Encryptor> m_encryptor;
  std::unique_ptr<Decryptor> m_decryptor;
  struct PcapTxRx{
    pcap_t *tx= nullptr;
    pcap_t *rx= nullptr;
  };
  std::vector<PcapTxRx> m_pcap_handles;
  // temporary
  std::mutex m_tx_mutex;
  bool keep_receiving= true;
  int m_n_receiver_errors=0;
  std::unique_ptr<std::thread> m_receive_thread;
  std::vector<pollfd> m_receive_pollfds;
  std::chrono::steady_clock::time_point m_last_receiver_error_log=std::chrono::steady_clock::now();
  static constexpr auto RADIO_PORT_SESSION_KEY_PACKETS=25;
  // for calculating the packet loss on the rx side
  seq_nr::Helper m_seq_nr_helper;
  OUTPUT_DATA_CALLBACK m_output_cb= nullptr;
  // Receiving packet statistics
  struct RxPacketStatsPerCard{
    // total number of received packets (can come from non-wb, too)
    uint64_t count_received_packets=0;
    // total number of successfully validated & decrypted packets
    uint64_t count_valid_packets=0;
  };
  std::vector<RxPacketStatsPerCard> m_rx_packet_stats;
  std::map<int,SPECIFIC_OUTPUT_DATA_CB> m_specific_callbacks;
 private:
  void announce_session_key_if_needed();
  void send_session_key();;
  void loop_receive_packets();
  int loop_iter(int rx_index);
  void on_new_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  // returns true if packet could be decrypted successfully
  bool process_received_data_packet(int wlan_idx,uint8_t radio_port,const uint8_t *pkt_payload,size_t pkt_payload_size);
  void on_valid_packet(uint64_t nonce,int wlan_index,uint8_t radioPort,const uint8_t *data, std::size_t data_len);
  // After calling this method, the injected packets will use a different radiotap header
  // I'd like to use an atomic instead of mutex, but unfortunately some compilers don't eat atomic struct
  void threadsafe_update_radiotap_header(const RadiotapHeader::UserSelectableParams& params);
};

#endif  // WIFIBROADCAST_TXRXINSTANCE_H
