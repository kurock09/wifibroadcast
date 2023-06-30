//
// Created by consti10 on 27.06.23.
//

#include "../src/TxRxInstance.h"
#include "RandomBufferPot.hpp"
#include "../src/WBTransmitter2.h"
#include "../src/WBReceiver2.h"
#include "../src/wifibroadcast-spdlog.h"

int main(int argc, char *const *argv) {

  auto card="wlxac9e17596103";
  std::vector<std::string> cards{card};
  TxRxInstance::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.set_direction= true;

  std::shared_ptr<TxRxInstance> txrx=std::make_shared<TxRxInstance>(cards,options_txrx);

  const bool enable_fec= true;
  WBTransmitter2::Options options_tx{};
  options_tx.radio_port=10;
  options_tx.enable_fec= enable_fec;
  std::unique_ptr<WBTransmitter2> wb_tx=std::make_unique<WBTransmitter2>(txrx,options_tx);

  WBReceiver2::Options options_rx{};
  options_rx.radio_port=10;
  options_rx.enable_fec= enable_fec;
  std::unique_ptr<WBReceiver2> wb_rx=std::make_unique<WBReceiver2>(txrx,options_rx);
  auto console=wifibroadcast::log::create_or_get("out_cb");
  auto cb=[&console](const uint8_t *payload, const std::size_t payloadSize){
      console->debug("Got data {}",payloadSize);
  };
  wb_rx->set_callback(cb);

  txrx->start_receiving();

  const auto randomBufferPot = std::make_unique<RandomBufferPot>(1000, 1024);

  while (true){
    for(int i=0;i<100;i++){
      auto dummy_packet=randomBufferPot->getBuffer(i);
      //txrx->tx_inject_packet(0,dummy_packet->data(),dummy_packet->size());
      if(enable_fec){
        wb_tx->try_enqueue_block({dummy_packet},10,10);
      }else{
        wb_tx->try_enqueue_packet(dummy_packet);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds (500));
    }
  }
}