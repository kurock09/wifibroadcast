//
// Created by consti10 on 29.06.23.
//

#ifndef WIFIBROADCAST_WBSTREAMRX_H
#define WIFIBROADCAST_WBSTREAMRX_H

#include "FECDisabled.hpp"
#include "FECEnabled.h"
#include "HelperSources/Helper.hpp"
#include "HelperSources/SeqNrHelper.hpp"
#include "HelperSources/SequenceNumberDebugger.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "WBTxRx.h"
#include "wifibroadcast-spdlog.h"
#include "wifibroadcast.hpp"

class WBStreamRx {
 public:
  typedef std::function<void(const uint8_t *payload, const std::size_t payloadSize)> OUTPUT_DATA_CALLBACK;
  struct Options {
    // needs to match the radio port of the corresponding tx
    uint8_t radio_port = 0;
    // enable / disable fec
    bool enable_fec= true;
    // RX queue depth (max n of blocks that can be buffered in the rx pipeline)
    // Use 1 if you have a single RX card, since anything else can result in stuttering (but might/is required for multiple rx card(s))
    unsigned int rx_queue_depth=1;
    // overwrite the console used for logging
    std::shared_ptr<spdlog::logger> opt_console=nullptr;
    // enable / disable multi threading (decouples the processing of data from the thread that provided the data,
    // e.g. the thread inside WBTxRx
    //bool enable_threading= true;
  };
  WBStreamRx(std::shared_ptr<WBTxRx> txrx,Options options1);
  WBStreamRx(const WBStreamRx &) = delete;
  WBStreamRx &operator=(const WBStreamRx &) = delete;
  void set_callback(WBStreamRx::OUTPUT_DATA_CALLBACK output_data_callback);
  struct Statistics{
    int64_t n_input_packets=0;
    int64_t n_input_bytes=0;
    int curr_in_packets_per_second=0;
    int curr_in_bits_per_second=0;
  };
  Statistics get_latest_stats();
  // matches FECDecoder
  struct FECRxStats2 {
    // total block count
    uint64_t count_blocks_total = 0;
    // a block counts as "lost" if it was removed before being fully received or recovered
    uint64_t count_blocks_lost = 0;
    // a block counts as "recovered" if it was recovered using FEC packets
    uint64_t count_blocks_recovered = 0;
    // n of primary fragments that were reconstructed during the recovery process of a block
    uint64_t count_fragments_recovered = 0;
    // n of forwarded bytes
    uint64_t count_bytes_forwarded=0;
    MinMaxAvg<std::chrono::nanoseconds> curr_fec_decode_time{};
  };
  FECRxStats2 get_lates_fec_stats();
 private:
  const Options m_options;
  std::shared_ptr<WBTxRx> m_txrx;
  std::shared_ptr<spdlog::logger> m_console;
  // Callback that is called with the decoded data
  WBStreamRx::OUTPUT_DATA_CALLBACK m_out_cb= nullptr;
  int64_t m_n_input_packets=0;
  int64_t m_n_input_bytes=0;
  BitrateCalculator m_input_bitrate_calculator{};
  PacketsPerSecondCalculator m_input_packets_per_second_calculator{};
  // for calculating the current rx bitrate
  BitrateCalculator m_received_bitrate_calculator{};
  // On the rx, either one of those two is active at the same time. NOTE: nullptr until the first session key packet
  std::unique_ptr<FECDecoder> m_fec_decoder = nullptr;
  std::unique_ptr<FECDisabledDecoder2> m_fec_disabled_decoder = nullptr;
  seq_nr::Helper m_seq_nr_helper;
  void on_new_packet(uint64_t nonce,int wlan_index,const uint8_t *data, const std::size_t data_len);
  void on_decoded_packet(const uint8_t* data,int data_len);
};

#endif  // WIFIBROADCAST_WBSTREAMRX_H
