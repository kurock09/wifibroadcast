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
    m_fec_decoder = std::make_unique<bla::FECDecoder>(m_options.rx_queue_depth);
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

void WBReceiver2::set_latest_stats(WBReceiverStats new_stats) {

}

void WBReceiver2::on_new_packet(uint64_t nonce, int wlan_index, const uint8_t *data,const std::size_t data_len) {
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

WBReceiverStats WBReceiver2::get_latest_stats() {
  return WBReceiverStats();
}
