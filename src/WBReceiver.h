#ifndef CONSTI10_WIFIBROADCAST_WB_RECEIVER_H
#define CONSTI10_WIFIBROADCAST_WB_RECEIVER_H
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


 * МОЁ TRVVHVHGB
 */
#include "Encryption.hpp"
#include "FECDisabled.hpp"
#include "FECEnabled.hpp"
#include "HelperSources/Helper.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "HelperSources/SequenceNumberDebugger.hpp"
#include "HelperSources/SeqNrHelper.hpp"
#include "RawReceiver.hpp"
#include "WBReceiverStats.hpp"
#include "wifibroadcast-spdlog.h"
#include "wifibroadcast.hpp"

// A wifi card with more than 4 antennas still has to be found :)
static constexpr const auto MAX_N_ANTENNAS_PER_WIFI_CARD = 4;
//

struct ROptions {
  uint8_t radio_port = 0;
  // The wlan adapters to listen on
  std::vector<std::string> rxInterfaces;
  // file for encryptor
  // make optional for ease of use - with no keypair given the default "seed" is used
  std::optional<std::string> keypair = "gs.key";
  // RX queue depth (max n of blocks that can be buffered in the rx pipeline)
  // Use 1 if you have a single RX card, since anything else can result in stuttering (but might/is required for multiple rx card(s))
  unsigned int rx_queue_depth=1;
  // dirty, rssi on rtl8812au is "bugged", this discards the first rssi value reported by the card.
  bool rtl8812au_rssi_fixup=false;
};

class WBReceiver {
 public:
  typedef std::function<void(const uint8_t *payload, const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
  /**
   * This class processes the received wifi raw wifi data
   * (aggregation, FEC decoding) and forwards it via the callback.
   * Each instance has to be assigned with a Unique ID (same id as the corresponding tx instance).
   * @param options1 the options for this instance (some options - so to say - come from the tx instance)
   * @param output_data_callback Callback that is called with the decoded data, can be null for debugging.
   */
  WBReceiver(ROptions options1, OUTPUT_DATA_CALLBACK output_data_callback,std::shared_ptr<spdlog::logger> console= nullptr);
  WBReceiver(const WBReceiver &) = delete;
  WBReceiver &operator=(const WBReceiver &) = delete;
  // dump statistics
  void recalculate_statistics();
  /**
   * Process incoming data packets as long as nothing goes wrong (nothing should go wrong as long
   * as the computer does not crash or the wifi card disconnects).
   * NOTE: This class won't be able to receive any wifi packages until loop() is called.
   * NOTE: This blocks the calling thread (never returns unless stop looping is called).
   */
  void loop();
  void stop_looping();
  /**
   * Create a verbose string that gives debugging information about the current state of this wb receiver.
   * Since this one only reads, it is safe to call from any thread.
   * Note that this one doesn't print to stdout.
   * @return a string without new line at the end.
   */
  [[nodiscard]] std::string createDebugState() const;
  /**
   * Fetch the current / latest statistics, can be called in regular intervals.
   * Thread-safe and guaranteed to not block for a significant amount of time
   */
  WBReceiverStats get_latest_stats();
  // used by the scan channels feature
  void reset_all_rx_stats();
 private:
  /**
   * Process a packet received via pcap from any of the rx wifi card(s).
   * This is always called by the same thread.
   * @param wlan_idx the wifi card this packet was received on
   * @param hdr, @param pkt the packet (pcap packet layout)
   */
  void process_received_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt);
  /**
   * called every time we receive a session key packet
   */
  void process_received_session_key_packet(const WBSessionKeyPacket &sessionKeyPacket);
  /**
   * called every time we receive a data packet. Returns true if the packet could be decrypted &
   * processed by either the fec enabled or disabled impl.
   */
  bool process_received_data_packet(uint8_t wlan_idx,const uint8_t *pkt_payload,size_t pkt_payload_size);
 private:
  const ROptions m_options;
  std::shared_ptr<spdlog::logger> m_console;
  Decryptor m_decryptor;
  std::vector<StatsPerRxCard> m_stats_per_card;
  WBRxStats m_wb_rx_stats{};
  // for calculating the current rx bitrate
  BitrateCalculator m_received_bitrate_calculator{};
  //We know that once we get the first session key packet
  bool IS_FEC_ENABLED = false;
  // On the rx, either one of those two is active at the same time. NOTE: nullptr until the first session key packet
  std::unique_ptr<FECDecoder> m_fec_decoder = nullptr;
  std::unique_ptr<FECDisabledDecoder> m_fec_disabled_decoder = nullptr;
  //Ieee80211HeaderSeqNrCounter mSeqNrCounter;
  // Callback that is called with the decoded data
  const OUTPUT_DATA_CALLBACK m_output_data_callback;
  std::unique_ptr<MultiRxPcapReceiver> m_multi_pcap_receiver;
  std::mutex m_last_stats_mutex;
  WBReceiverStats m_last_stats{};
  void set_latest_stats(WBReceiverStats new_stats);
  seq_nr::Helper m_seq_nr_helper;
 public:
#ifdef ENABLE_ADVANCED_DEBUGGING
  // time between <packet arrives at pcap processing queue> <<->> <packet is pulled out of pcap by RX>
  AvgCalculator avgPcapToApplicationLatency;
  AvgCalculator2 avgLatencyBeaconPacketLatency;
#endif
};

#endif //CONSTI10_WIFIBROADCAST_WB_RECEIVER_H