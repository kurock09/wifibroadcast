//
// Created by consti10 on 02.07.23.
//

#ifndef WIFIBROADCAST_WBSTREAMRXUDP_H
#define WIFIBROADCAST_WBSTREAMRXUDP_H

#include "../WBStreamRx.h"
#include "SocketHelper.hpp"

class WBStreamRxUDP{
 public:
  WBStreamRxUDP(std::shared_ptr<WBTxRx> txrx,WBStreamRx::Options options,int udp_port_out){
   m_udp_out=std::make_unique<SocketHelper::UDPForwarder>(
        SocketHelper::ADDRESS_LOCALHOST,5601);
    wb_rx=std::make_unique<WBStreamRx>(txrx,options);
    auto console=wifibroadcast::log::create_or_get("out_cb");
    auto cb=[this](const uint8_t *payload, const std::size_t payloadSize){
      //console->debug("Got data {}",payloadSize);
      m_udp_out->forwardPacketViaUDP(payload,payloadSize);
    };
    wb_rx->set_callback(cb);
    console->info("Sending data to localhost:5601");
  }
  std::unique_ptr<SocketHelper::UDPForwarder> m_udp_out;
  std::unique_ptr<WBStreamRx> wb_rx;
 private:
};

#endif  // WIFIBROADCAST_WBSTREAMRXUDP_H
