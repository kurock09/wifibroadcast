//
// Created by consti10 on 30.06.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "../src/HelperSources/SocketHelper.hpp"
#include "RandomBufferPot.hpp"

/**
 * Simple example application that uses UDP as data input / output
 * Feed in udp packets on air -> get out udp packets on ground
 *
 * NOTE: The input stream is protected by FEC - but this serves only demo purposes here
 * For proper usage of FEC during wifibroadcast streaming (no latency overhead), please check out openhd.
 *
 * NOTE: This example does not support running another instance of it simultaneously - if you want to do multiplexing,
 * do it in c++ code, you cannot do it via shell anymore !
 *
 * When run as air: Expects UDP data on port 5600
 * When run as ground: Forwards UDP data to port 5601
 */
int main(int argc, char *const *argv) {
  std::string card="wlxac9e17596103";
  bool pcap_setdirection= true;
  bool is_air= false;
  int opt;
  while ((opt = getopt(argc, argv, "w:agd")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      case 'a':
        is_air= true;
        break ;
      case 'g':
        is_air= false;
        break ;
      case 'd':
        pcap_setdirection= false;
        break ;
      default: /* '?' */
      show_usage:
        fprintf(stderr,
                "Example hello %s [-a run as air] [-g run as ground] [-w wifi card to use] ...\n",
                argv[0]);
        exit(1);
    }
  }
  std::cout<<"Running as "<<(is_air ? "Air" : "Ground")<<" on card "<<card<<"\n";

  std::vector<std::string> cards{card};
  WBTxRx::Options options_txrx{};
  options_txrx.rtl8812au_rssi_fixup= true;
  //options_txrx.set_direction= false;
  options_txrx.set_direction= pcap_setdirection;
  options_txrx.log_all_received_validated_packets= false;

  std::shared_ptr<WBTxRx> txrx=std::make_shared<WBTxRx>(cards,options_txrx);

  if(is_air){
    // UDP in and inject packets
    const bool enable_fec= true;
    WBStreamTx::Options options_tx{};
    options_tx.radio_port=10;
    options_tx.enable_fec= enable_fec;
    std::unique_ptr<WBStreamTx> wb_tx=std::make_unique<WBStreamTx>(txrx,options_tx);
    // we need to buffer packets due to udp
    std::vector<std::shared_ptr<std::vector<uint8_t>>> block;
    auto cb_udp_in=[&wb_tx,&block](const uint8_t *payload, const std::size_t payloadSize){
      auto packet=std::make_shared<std::vector<uint8_t>>(payload,payload+payloadSize);
      block.push_back(packet);
      if(block.size()==8){
        wb_tx->try_enqueue_block(block,100,20);
        block.resize(0);
      }
    };
    std::unique_ptr<SocketHelper::UDPReceiver> m_udp_in=std::make_unique<SocketHelper::UDPReceiver>(
        SocketHelper::ADDRESS_LOCALHOST,5600,cb_udp_in);
    m_udp_in->runInBackground();
    std::cout<<"Expecting data on localhost:5600\n";
  }else{
    std::unique_ptr<SocketHelper::UDPForwarder> m_udp_out=std::make_unique<SocketHelper::UDPForwarder>(
        SocketHelper::ADDRESS_LOCALHOST,5601);
    // listen for packets and udp out
    WBStreamRx::Options options_rx{};
    options_rx.radio_port=10;
    options_rx.enable_fec= true;
    std::unique_ptr<WBStreamRx> wb_rx=std::make_unique<WBStreamRx>(txrx,options_rx);
    auto console=wifibroadcast::log::create_or_get("out_cb");
    auto cb=[&console,&m_udp_out](const uint8_t *payload, const std::size_t payloadSize){
      //console->debug("Got data {}",payloadSize);
      m_udp_out->forwardPacketViaUDP(payload,payloadSize);
    };
    wb_rx->set_callback(cb);
    txrx->start_receiving();
  }
  auto lastLog=std::chrono::steady_clock::now();
  while (true){
    std::this_thread::sleep_for(std::chrono::milliseconds (500));
    const auto elapsed_since_last_log=std::chrono::steady_clock::now()-lastLog;
    if(elapsed_since_last_log>std::chrono::seconds(1)){
      lastLog=std::chrono::steady_clock::now();
      if(is_air){
        auto txStats=txrx->get_tx_stats();
        std::cout<<txStats<<"\n";
      }else{
        auto rxStats=txrx->get_rx_stats();
        auto rssi=txrx->get_rx_stats_for_card(0);
        std::cout<<rxStats<<"\n";
        std::cout<<"RSSI:"<<(int)rssi.rssi_for_wifi_card.last_rssi<<"\n";
      }
    }
  }
}