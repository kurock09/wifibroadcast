//
// Created by consti10 on 27.06.23.
//

#ifndef WIFIBROADCAST_WBTXRX_H
#define WIFIBROADCAST_WBTXRX_H

#include <sys/poll.h>

#include <atomic>
#include <map>
#include <utility>

#include "Encryption.hpp"
#include "RSSIForWifiCard.hpp"
#include "RadiotapHeader.hpp"
#include "SeqNrHelper.hpp"
#include "TimeHelper.hpp"
#include "wifibroadcast.hpp"

/**
 * Wraps one or more wifi card in monitor mode
 * Provides easy interface to inject data packets and register a callback to
 * process received data packets.
 * Adds packet encryption and authentication via libsodium (can be disabled for
 * performance) Allows multiplexing of multiple data streams (radio_port) Quick
 * usage description by example:
 * # System 1: card 1
 * # System 2: card 2
 * air in between card 1 and card 2
 * Create an instance of WBTxRx on both system 1
 * and system 2 inject packets using WBTxRx on system 1 -> receive them
 * using WBTxRx on system 2 inject packets using WBTxRx on system 2
 * -> receive them using WBTxRx on system 1
 */
class WBTxRx {
 public:
  struct Options{
    // file for encryptor
    // make optional for ease of use - with no keypair given the default "seed" is used
    std::optional<std::string> encryption_key = std::nullopt;
    // dirty, rssi on rtl8812au is "bugged", this discards the first rssi value reported by the card.
    bool rtl8812au_rssi_fixup=false;
    // TODO
    bool set_direction= true;
    // thy spam the console, but usefully for debugging
    // log all received packets (regardless where they are from)
    bool log_all_received_packets= false;
    bool log_all_received_validated_packets= false;
    // more verbose tx logging
    bool advanced_debugging_tx = false;
    // more verbose rx logging
    bool advanced_debugging_rx = false;
    // advanced latency related debugging
    bool advanced_latency_debugging_rx= false;
    // set sched_param = max realtime on the thread that pulls out the packets
    bool receive_thread_max_realtime= true;
  };
  explicit WBTxRx(std::vector<std::string> wifi_cards,Options options1);
  WBTxRx(const WBTxRx &) = delete;
  WBTxRx &operator=(const WBTxRx &) = delete;
  ~WBTxRx();
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
   * A typical stream RX (aka the receiver for a specific multiplexed stream) needs to react to events during streaming.
   * For lowest latency, we do this via callback(s) that are called directly.
   * You can register listening on these events and also deregister them here.
   * @param nonce: the nonce of the received packet (can be used for sequence numbering)
   * @param wlan_index: the card on which the packet was received (in case there are multiple cards used for wb)
   * @param radio_port: the multiplex index used to separate streams during injection
   */
  typedef std::function<void(uint64_t nonce,int wlan_index,const uint8_t *data, const std::size_t data_len)> SPECIFIC_OUTPUT_DATA_CB;
  typedef std::function<void()> NEW_SESSION_CB;
  struct StreamRxHandler{
    uint8_t radio_port; // For which multiplexed stream this handles events
    SPECIFIC_OUTPUT_DATA_CB cb_packet; // called every time a packet for this stream is received
    NEW_SESSION_CB cb_session; // called every time a new session is detected
    StreamRxHandler(uint8_t radio_port1,SPECIFIC_OUTPUT_DATA_CB cb_packet1,NEW_SESSION_CB cb_session1)
    :radio_port(radio_port1),cb_packet(std::move(cb_packet1)),cb_session(std::move(cb_session1)){}
  };
  void rx_register_stream_handler(std::shared_ptr<StreamRxHandler> handler);
  void rx_unregister_stream_handler(uint8_t radio_port);
  typedef std::function<void(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len)> OUTPUT_DATA_CALLBACK;
  // register callback that is called each time a valid packet is received (any multiplexed stream)
  void rx_register_callback(OUTPUT_DATA_CALLBACK cb);

  /**
   * Receiving packets happens in the background in another thread.
   */
  void start_receiving();
  void stop_receiving();

   // These are for updating injection parameters at run time. They will be applied on the next injected packet.
   // They are generally thread-safe. See RadiotapHeader for more information on what these parameters do.
   // After calling this method, the injected packets will use a different radiotap header
   // I'd like to use an atomic instead of mutex, but unfortunately some compilers don't eat atomic struct
   void tx_threadsafe_update_radiotap_header(const RadiotapHeader::UserSelectableParams& params);
   void tx_update_mcs_index(uint8_t mcs_index);
   void tx_update_channel_width(int width_mhz);
   void tx_update_stbc(int stbc);
   void tx_update_guard_interval(bool short_gi);
   void tx_update_ldpc(bool ldpc);

   // Statistics
   struct TxStats{
     int64_t n_injected_packets=0;
     int64_t n_injected_bytes=0;
     // tx errors, first sign the tx can't keep up with the provided bitrate
     int32_t count_tx_injections_error_hint=0;
   };
   struct RxStats{
     // Total count of received packets / bytes - can be from another wb tx, but also from someone else using wifi
     // Usefully to reason about pollution, but this does not include non-wifi packets (e.g. bluetooth, dji)
     int64_t count_p_any=0;
     int64_t count_bytes_any=0;
     // Total count of valid received packets / bytes (decrypted)
     int64_t count_p_valid=0;
     int64_t count_bytes_valid=0;
     // Those values are recalculated in X second intervals.
     // If no data arrives for a long time, they report -1 instead of 0
     int32_t curr_packet_loss=-1;
     int32_t curr_packets_per_second=-1;
     int32_t curr_bytes_per_second=-1;
     // n received valid session key packets
     int n_received_valid_session_key_packets=0;
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
   TxStats get_tx_stats();
   RxStats get_rx_stats();
   RxStatsPerCard get_rx_stats_for_card(int card_index);
   // used by openhd during frequency scan
   void rx_reset_stats();
 private:
  const Options m_options;
  std::shared_ptr<spdlog::logger> m_console;
  std::vector<std::string> m_wifi_cards;
  std::chrono::steady_clock::time_point m_session_key_announce_ts{};
  RadiotapHeader::UserSelectableParams m_radioTapHeaderParams{};
  RadiotapHeader m_radiotap_header;
  Ieee80211Header mIeee80211Header{};
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
  RxStats m_rx_stats{};
  TxStats m_tx_stats{};
  // a tx error is thrown if injecting the packet takes longer than MAX_SANE_INJECTION_TIME,
  // which hints at a overflowing tx queue (unfortunately I don't know a way to directly get the tx queue yet)
  // However, this hint can be misleading - for example, during testing (MCS set to 3) and with about 5MBit/s video after FEC
  // I get about 5 tx error(s) per second with my atheros, but it works fine. This workaround also seems to not work at all
  // with the RTL8812au.
  static constexpr std::chrono::nanoseconds MAX_SANE_INJECTION_TIME=std::chrono::milliseconds(5);
  std::vector<RxStatsPerCard> m_rx_packet_stats;
  std::map<int,std::shared_ptr<StreamRxHandler>> m_rx_handlers;
  // If each iteration pulls too many packets out your CPU is most likely too slow
  AvgCalculatorSize m_n_packets_polled_pcap;
  AvgCalculator m_packet_host_latency;
 private:
  // we announce the session key in regular intervals if data is currently being injected (tx_ is called)
  void announce_session_key_if_needed();
  // send out the session key
  void send_session_key();
  // called by the receive thread, wait for data to become available then pull data
  void loop_receive_packets();
  // pull data from a pcap handle which has data available
  int loop_iter(int rx_index);
  // called every time we have a new (raw) data packet
  void on_new_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  // verify and decrypt the packet if possible
  // returns true if packet could be decrypted successfully
  bool process_received_data_packet(int wlan_idx,uint8_t radio_port,const uint8_t *pkt_payload,size_t pkt_payload_size);
  // called avery time we have successfully decrypted a packet
  void on_valid_packet(uint64_t nonce,int wlan_index,uint8_t radioPort,const uint8_t *data, std::size_t data_len);
};

static std::ostream& operator<<(std::ostream& strm, const WBTxRx::TxStats& data){
  auto tmp=fmt::format("TxStats[injected packets:{} bytes:{} tx errors:{}]",data.n_injected_packets,data.n_injected_bytes,data.count_tx_injections_error_hint);
  strm<<tmp;
  return strm;
}
static std::ostream& operator<<(std::ostream& strm, const WBTxRx::RxStats& data){
  auto tmp=fmt::format("RxStats[packets any:{} session:{} decrypted:{} Loss:{} pps:{} bps:{}]",
                         data.count_p_any,data.n_received_valid_session_key_packets,data.count_p_valid,
                         data.curr_packet_loss,data.curr_packets_per_second,data.curr_bytes_per_second);
  strm<<tmp;
  return strm;
}

#endif  // WIFIBROADCAST_WBTXRX_H
