//
// Created by consti10 on 29.06.23.
//

#ifndef WIFIBROADCAST_WBRECEIVER2_H
#define WIFIBROADCAST_WBRECEIVER2_H

#include "FECDisabled2.hpp"
#include "FECEnabled2.h"
#include "HelperSources/Helper.hpp"
#include "HelperSources/SeqNrHelper.hpp"
#include "HelperSources/SequenceNumberDebugger.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "TxRxInstance.h"
#include "WBReceiverStats.hpp"
#include "wifibroadcast-spdlog.h"
#include "wifibroadcast.hpp"

struct ROptions2 {
  uint8_t radio_port = 0;
  // enable / disable fec
  bool enable_fec= true;
  // RX queue depth (max n of blocks that can be buffered in the rx pipeline)
  // Use 1 if you have a single RX card, since anything else can result in stuttering (but might/is required for multiple rx card(s))
  unsigned int rx_queue_depth=1;
  // dirty, rssi on rtl8812au is "bugged", this discards the first rssi value reported by the card.
  bool rtl8812au_rssi_fixup=false;
  // overwrite the console used for logging
  std::shared_ptr<spdlog::logger> opt_console=nullptr;
};

class WBReceiver2 {
 public:
  typedef std::function<void(const uint8_t *payload, const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
  WBReceiver2(std::shared_ptr<TxRxInstance> txrx,ROptions2 options1);
  WBReceiver2(const WBReceiver2 &) = delete;
  WBReceiver2 &operator=(const WBReceiver2 &) = delete;
  void set_callback(WBReceiver2::OUTPUT_DATA_CALLBACK output_data_callback);
 private:
  const ROptions2 m_options;
  std::shared_ptr<TxRxInstance> m_txrx;
  std::shared_ptr<spdlog::logger> m_console;
  std::vector<StatsPerRxCard> m_stats_per_card;
  // Callback that is called with the decoded data
  WBReceiver2::OUTPUT_DATA_CALLBACK m_out_cb= nullptr;
  WBRxStats m_wb_rx_stats{};
  // for calculating the current rx bitrate
  BitrateCalculator m_received_bitrate_calculator{};
  // On the rx, either one of those two is active at the same time. NOTE: nullptr until the first session key packet
  std::unique_ptr<bla::FECDecoder> m_fec_decoder = nullptr;
  std::unique_ptr<FECDisabledDecoder2> m_fec_disabled_decoder = nullptr;
  std::mutex m_last_stats_mutex;
  WBReceiverStats m_last_stats{};
  void set_latest_stats(WBReceiverStats new_stats);
  seq_nr::Helper m_seq_nr_helper;
  void on_new_packet(uint64_t nonce,int wlan_index,const uint8_t *data, const std::size_t data_len);
  void on_decoded_packet(const uint8_t* data,int data_len);
};

#endif  // WIFIBROADCAST_WBRECEIVER2_H
