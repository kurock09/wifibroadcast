//
// Created by consti10 on 28.06.23.
//

#ifndef WIFIBROADCAST_WBTRANSMITTER2_H
#define WIFIBROADCAST_WBTRANSMITTER2_H

#include <queue>
#include <thread>
#include <variant>

#include "../moodycamel/concurrentqueue/blockingconcurrentqueue.h"
#include "../moodycamel/readerwriterqueue/readerwritercircularbuffer.h"
#include "FECDisabled2.hpp"
#include "FECEnabled2.h"
#include "TimeHelper.hpp"
#include "TxRxInstance.h"
#include "WBTransmitterStats.hpp"

class WBTransmitter2 {
 public:
  struct Options {
    // the radio port is what is used as an index to multiplex multiple streams (telemetry,video,...)
    // into the one wfb stream
    uint8_t radio_port = 1;
    // size of packet data queue
    int packet_data_queue_size=64;
    // size of block / frame data queue
    int block_data_queue_size=2;
    // Even though setting the fec_k parameter / n of primary fragments creates similar characteristics as a link
    // without fec, we have a special impl. when fec is disabled, since there we allow packets out of order and with fec_k == 1 you'd have
    // packet re-ordering / packets out of order are not possible.
    bool enable_fec= true;
    // for development, log time items spend in the data queue (it should be close to 0)
    bool log_time_spent_in_atomic_queue=false;
    // overwrite the console used for logging
    std::shared_ptr<spdlog::logger> opt_console=nullptr;
  };
  WBTransmitter2(std::shared_ptr<TxRxInstance> txrx,Options options);
  WBTransmitter2(const WBTransmitter2 &) = delete;
  WBTransmitter2 &operator=(const WBTransmitter2 &) = delete;
  ~WBTransmitter2();
  /**
   * Enqueue a packet to be processed. FEC needs to be disabled in this mode.
   * Guaranteed to return immediately.
   * This method is not thread-safe.
   * @param packet the packet (data) to enqueue
   * @return true on success (space in the packet queue), false otherwise
   */
  bool try_enqueue_packet(std::shared_ptr<std::vector<uint8_t>> packet);
  /**
   * Enqueue a block (most likely a frame) to be processed, FEC needs to be enabled in this mode.
   * Guaranteed to return immediately.
   * This method is not thread-safe.
   * If the n of fragments exceeds @param max_block_size, the block is split into one or more sub-blocks.
   * @return true on success (space in the block queue), false otherwise
   */
  bool try_enqueue_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments,int max_block_size,int fec_overhead_perc);
  // statistics
  WBTxStats get_latest_stats();
  // only valid when actually doing FEC
  FECTxStats get_latest_fec_stats();
 private:
  const Options options;
  std::shared_ptr<TxRxInstance> m_txrx;
  // On the tx, either one of those two is active at the same time
  std::unique_ptr<bla::FECEncoder> m_fec_encoder = nullptr;
  std::unique_ptr<FECDisabledEncoder2> m_fec_disabled_encoder = nullptr;
  // We have two data queues with a slightly different layout (depending on the selected operating mode)
  struct EnqueuedPacket {
    std::chrono::steady_clock::time_point enqueue_time_point=std::chrono::steady_clock::now();
    std::shared_ptr<std::vector<uint8_t>> data;
  };
  struct EnqueuedBlock {
    std::chrono::steady_clock::time_point enqueue_time_point=std::chrono::steady_clock::now();
    int max_block_size;
    int fec_overhead_perc;
    std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments;
  };
  // Used if fec is disabled, for telemetry data
  std::unique_ptr<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedPacket>>> m_packet_queue;
  // Used if fec is enabled, for video data
  std::unique_ptr<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedBlock>>> m_block_queue;
  // The thread that consumes the provided packets or blocks, set to sched param realtime
  std::unique_ptr<std::thread> m_process_data_thread;
  bool m_process_data_thread_run=true;
  uint64_t m_n_dropped_packets=0;
  // count of bytes we got passed (aka for example, what the video encoder produced - does not include FEC)
  uint64_t m_count_bytes_data_provided =0;
  BitrateCalculator m_bitrate_calculator_data_provided{};
  // Time fragments / blocks spend in the non-blocking atomic queue.
  AvgCalculator m_queue_time_calculator;
  std::shared_ptr<spdlog::logger> m_console;
  void loop_process_data();
  void process_enqueued_packet(const EnqueuedPacket& packet);
  void process_enqueued_block(const EnqueuedBlock& block);
  void send_packet(const uint8_t* packet,int packet_len);
};

#endif  // WIFIBROADCAST_WBTRANSMITTER2_H
