//
// Created by consti10 on 29.06.23.
//

#include "WBReceiver2.h"

#include <utility>

WBReceiver2::WBReceiver2(std::shared_ptr<TxRxInstance> txrx,Options options1)
    : m_txrx(txrx),
      m_options(options1)
{
  assert(m_txrx);
  if(m_options.opt_console){
    m_console=m_options.opt_console;
  }else{
    m_console=wifibroadcast::log::create_or_get("wb_rx"+std::to_string(m_options.radio_port));
  }
  if(m_options.enable_fec){
    m_fec_decoder = std::make_unique<FECDecoder>(m_options.rx_queue_depth);
    auto cb=[this](const uint8_t *data, int data_len){
      on_decoded_packet(data,data_len);
    };
    m_fec_decoder->mSendDecodedPayloadCallback = cb;
  }else{
    m_fec_disabled_decoder = std::make_unique<FECDisabledDecoder2>();
    auto cb=[this](const uint8_t *data, int data_len){
      on_decoded_packet(data,data_len);
    };
    m_fec_disabled_decoder->mSendDecodedPayloadCallback = cb;
  }
  auto cb=[this](uint64_t nonce,int wlan_index,const uint8_t *data, const std::size_t data_len){
    this->on_new_packet(nonce,wlan_index,data,data_len);
  };
  m_txrx->rx_register_specific_cb(m_options.radio_port,cb);
}

void WBReceiver2::set_callback(WBReceiver2::OUTPUT_DATA_CALLBACK output_data_callback) {
  m_out_cb=std::move(output_data_callback);
}


void WBReceiver2::on_new_packet(uint64_t nonce, int wlan_index, const uint8_t *data,const std::size_t data_len) {
  m_n_input_packets++;
  m_n_input_bytes+=data_len;
  if(m_options.enable_fec){
    m_fec_decoder->validate_and_process_packet(data,data_len);
  }else{
    m_fec_disabled_decoder->process_packet(data,data_len);
  }
}

void WBReceiver2::on_decoded_packet(const uint8_t *data, int data_len) {
  if(m_out_cb){
    m_out_cb(data,data_len);
  }
}

WBReceiver2::Statistics WBReceiver2::get_latest_stats() {
  WBReceiver2::Statistics ret;
  ret.n_input_bytes=m_n_input_bytes;
  ret.n_input_packets=m_n_input_packets;
  ret.curr_in_packets_per_second=
      m_input_packets_per_second_calculator.get_last_or_recalculate(
          m_n_input_packets,std::chrono::seconds(2));
  ret.curr_in_bits_per_second=m_input_bitrate_calculator.get_last_or_recalculate(
      m_n_input_bytes,std::chrono::seconds(2));
  return ret;
}

WBReceiver2::FECRxStats2 WBReceiver2::get_lates_fec_stats() {
  WBReceiver2::FECRxStats2 ret;
  if(m_fec_decoder){
    auto stats=m_fec_decoder->stats;
    ret.count_blocks_lost= stats.count_blocks_lost;
    ret.count_blocks_recovered=stats.count_blocks_recovered;
    ret.count_blocks_total=stats.count_blocks_total;
    ret.count_fragments_recovered=stats.count_fragments_recovered;
    ret.curr_fec_decode_time=stats.curr_fec_decode_time;
  }
  return ret;
}
