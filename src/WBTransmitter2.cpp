//
// Created by consti10 on 28.06.23.
//

#include "WBTransmitter2.h"

#include <utility>

#include "BlockSizeHelper.hpp"
#include "SchedulingHelper.hpp"

WBTransmitter2::WBTransmitter2(std::shared_ptr<TxRxInstance> txrx,Options options1)
    :options(options1),
      m_txrx(txrx)
{
  assert(m_txrx);
  if(options.opt_console){
    m_console=options.opt_console;
  }else{
    m_console=wifibroadcast::log::create_or_get("wb_tx"+std::to_string(options.radio_port));
  }
  assert(m_console);
  m_console->info("WBTransmitter radio_port: {} fec:{}", options.radio_port, options.enable_fec ? "Y" : "N");
  if(options.enable_fec){
    m_block_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedBlock>>>(options.block_data_queue_size);
    m_fec_encoder = std::make_unique<bla::FECEncoder>();
    auto cb=[this](const uint8_t* packet,int packet_len){
      send_packet(packet,packet_len);
    };
    m_fec_encoder->outputDataCallback=cb;
  }else{
    m_packet_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedPacket>>>(options.packet_data_queue_size);
    m_fec_disabled_encoder = std::make_unique<FECDisabledEncoder2>();
    auto cb=[this](const uint8_t* packet,int packet_len){
      send_packet(packet,packet_len);
    };
    m_fec_disabled_encoder->outputDataCallback=cb;
  }
  m_process_data_thread_run=true;
  m_process_data_thread=std::make_unique<std::thread>(&WBTransmitter2::loop_process_data, this);
}

WBTransmitter2::~WBTransmitter2() {
  m_process_data_thread_run= false;
  if(m_process_data_thread && m_process_data_thread->joinable()){
    m_process_data_thread->join();
  }
}

bool WBTransmitter2::try_enqueue_packet(std::shared_ptr<std::vector<uint8_t>> packet) {
  assert(!options.enable_fec);
  auto item=std::make_shared<EnqueuedPacket>();
  item->data=std::move(packet);
  const bool res= m_packet_queue->try_enqueue(item);
  if(!res){
    m_n_dropped_packets++;
    // TODO not exactly the correct solution - include dropped packets in the seq nr, such that they are included
    // in the loss (perc) on the ground
    //m_curr_seq_nr++;
  }
  return res;
}

bool WBTransmitter2::try_enqueue_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments,int max_block_size, int fec_overhead_perc) {
  assert(options.enable_fec);
  for(const auto& fragment:fragments){
    if (fragment->empty() || fragment->size() > bla::FEC_MAX_PAYLOAD_SIZE) {
      m_console->warn("Fed fragment with incompatible size:{}",fragment->size());
      return false;
    }
  }
  auto item=std::make_shared<EnqueuedBlock>();
  item->fragments=fragments;
  item->max_block_size=max_block_size;
  item->fec_overhead_perc=fec_overhead_perc;
  const bool res= m_block_queue->try_enqueue(item);
  if(!res){
    m_n_dropped_packets+=fragments.size();
    //m_curr_seq_nr+=fragments.size();
  }
  return res;
}

WBTransmitter2::FECStats WBTransmitter2::get_latest_fec_stats() {
  WBTransmitter2::FECStats ret{};
  if(m_fec_encoder){
    ret.curr_fec_encode_time=m_fec_encoder->m_curr_fec_block_encode_time;
    ret.curr_fec_block_length=m_fec_encoder->m_curr_fec_block_sizes;
  }
  return ret;
}

WBTransmitter2::Statistics WBTransmitter2::get_latest_stats() {
  WBTransmitter2::Statistics ret{};
  ret.n_provided_bytes=m_count_bytes_data_provided;
  ret.n_provided_packets=m_n_input_packets;
  ret.n_injected_packets= m_n_injected_packets;
  ret.n_injected_bytes=static_cast<int64_t>(m_count_bytes_data_injected);
  ret.current_injected_bits_per_second=m_bitrate_calculator_injected_bytes.get_last_or_recalculate(
      m_count_bytes_data_injected,std::chrono::seconds(2));
  ret.current_provided_bits_per_second=
      m_bitrate_calculator_data_provided.get_last_or_recalculate(
          m_count_bytes_data_provided,std::chrono::seconds(2));
  ret.n_dropped_packets=m_n_dropped_packets;
  ret.current_injected_packets_per_second=m_packets_per_second_calculator.get_last_or_recalculate(
          m_n_injected_packets,std::chrono::seconds(2));
  return ret;
}


void WBTransmitter2::loop_process_data() {
  SchedulingHelper::setThreadParamsMaxRealtime();
  static constexpr std::int64_t timeout_usecs=100*1000;
  if(options.enable_fec){
    std::shared_ptr<EnqueuedBlock> frame;
    while (m_process_data_thread_run){
      if(m_block_queue->wait_dequeue_timed(frame,timeout_usecs)){
        m_queue_time_calculator.add(std::chrono::steady_clock::now()-frame->enqueue_time_point);
        if(m_queue_time_calculator.get_delta_since_last_reset()>std::chrono::seconds(1)){
          if(options.log_time_spent_in_atomic_queue){
            m_console->debug("Time in queue {}",m_queue_time_calculator.getAvgReadable());
          }
          m_queue_time_calculator.reset();
        }
        process_enqueued_block(*frame);
      }
    }
  }else{
    std::shared_ptr<EnqueuedPacket> packet;
    while (m_process_data_thread_run){
      if(m_packet_queue->wait_dequeue_timed(packet,timeout_usecs)){
        m_queue_time_calculator.add(std::chrono::steady_clock::now()-packet->enqueue_time_point);
        if(m_queue_time_calculator.get_delta_since_last_reset()>std::chrono::seconds(1)){
          if(options.log_time_spent_in_atomic_queue){
            m_console->debug("Time in queue {}",m_queue_time_calculator.getAvgReadable());
          }
          m_queue_time_calculator.reset();
        }
        process_enqueued_packet(*packet);
      }
    }
  }
}

void WBTransmitter2::process_enqueued_packet(const WBTransmitter2::EnqueuedPacket& packet) {
  m_fec_disabled_encoder->encodePacket(packet.data->data(),packet.data->size());
  m_n_input_packets++;
  m_count_bytes_data_provided+=packet.data->size();
}

void WBTransmitter2::process_enqueued_block(const WBTransmitter2::EnqueuedBlock& block) {
  auto blocks=blocksize::split_frame_if_needed(block.fragments,block.max_block_size);
  for(auto& x_block :blocks){
    const auto n_secondary_f=bla::calculate_n_secondary_fragments(x_block.size(),block.fec_overhead_perc);
    m_fec_encoder->encode_block(x_block,n_secondary_f);
  }
  m_n_input_packets+=block.fragments.size();
  for(const auto& fragment:block.fragments){
    m_count_bytes_data_provided +=fragment->size();
  }
}

void WBTransmitter2::send_packet(const uint8_t* packet, int packet_len) {
  m_txrx->tx_inject_packet(options.radio_port,packet,packet_len);
  m_n_injected_packets++;
  m_count_bytes_data_injected+=packet_len;
}
