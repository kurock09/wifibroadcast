
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
 */
#include "RawReceiver.hpp"
#include "WBReceiver.h"
#include "wifibroadcast.hpp"
#include "HelperSources/SchedulingHelper.hpp"
#include <cassert>
#include <cstdio>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <memory>
#include <string>
#include <chrono>
#include <sstream>
#include <utility>

WBReceiver::WBReceiver(ROptions options1, OUTPUT_DATA_CALLBACK output_data_callback,
                       std::optional<OpenHDStatisticsWriter::STATISTICS_CALLBACK> statistics_callback) :
    options(std::move(options1)),
    mDecryptor(options.keypair),
    mOutputDataCallback(std::move(output_data_callback)) {
  if(statistics_callback.has_value()){
    openHdStatisticsWriter._statistics_callback=statistics_callback.value();
  }
  std::cout << "WFB_VERSION:" << WFB_VERSION << "\n";
  receiver = std::make_unique<MultiRxPcapReceiver>(options.rxInterfaces, options.radio_port, options1.log_interval,
                                                   notstd::bind_front(&WBReceiver::processPacket, this),
                                                   notstd::bind_front(&WBReceiver::dump_stats, this));
  std::cout << "WFB-RX RADIO_PORT:" << (int) options.radio_port << "Logging enabled:"
            << (options.enableLogAlive ? "Y" : "N") << "\n";
}

void WBReceiver::loop() {
  receiver->loop();
}

std::string WBReceiver::createDebugState() const {
  std::stringstream ss;
  ss<<wb_rx_stats<<"\n";
  if(mFECDDecoder){
    ss<<"\n"; //TODO
  }
  return ss.str();
}

void WBReceiver::dump_stats() {
  // first forward to OpenHD
  std::optional<FECStreamStats> fec_stream_stats=std::nullopt;
  if(mFECDDecoder){
    fec_stream_stats=mFECDDecoder->stats;
  }
  OpenHDStatisticsWriter::Data data{options.radio_port,rssiForWifiCard,wb_rx_stats,fec_stream_stats};
  openHdStatisticsWriter.writeStats(data);
  //timestamp in ms
  const uint64_t runTime =
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - INIT_TIME).count();
  if (options.enableLogAlive) {
    for (auto &wifiCard: rssiForWifiCard) {
      // no new rssi values for this card since the last call
      if (wifiCard.count_all == 0)continue;
      std::cout << "RSSI Count|Min|Max|Avg:\t" << (int) wifiCard.count_all << ":" << (int) wifiCard.rssi_min << ":"
                << (int) wifiCard.rssi_max << ":" << (int) wifiCard.getAverage() << "\n";
      wifiCard.reset();
    }
    std::stringstream ss;
    std::cout<<createDebugState();
  }
  // it is actually much more understandable when I use the absolute values for the logging
#ifdef ENABLE_ADVANCED_DEBUGGING
  std::cout<<"avgPcapToApplicationLatency: "<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
  //std::cout<<"avgLatencyBeaconPacketLatency"<<avgLatencyBeaconPacketLatency.getAvgReadable()<<"\n";
  //std::cout<<"avgLatencyBeaconPacketLatencyX:"<<avgLatencyBeaconPacketLatency.getNValuesLowHigh(20)<<"\n";
  //std::cout<<"avgLatencyPacketInQueue"<<avgLatencyPacketInQueue.getAvgReadable()<<"\n";
#endif
}

void WBReceiver::processPacket(const uint8_t WLAN_IDX, const pcap_pkthdr &hdr, const uint8_t *pkt) {
#ifdef ENABLE_ADVANCED_DEBUGGING
  const auto tmp=GenericHelper::timevalToTimePointSystemClock(hdr.ts);
  const auto latency=std::chrono::system_clock::now() -tmp;
  avgPcapToApplicationLatency.add(latency);
#endif
  wb_rx_stats.count_p_all++;
  // The radio capture header precedes the 802.11 header.
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt);
  if (parsedPacket == std::nullopt) {
    std::cerr << "Discarding packet due to pcap parsing error!\n";
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->frameFailedFCSCheck) {
    std::cerr << "Discarding packet due to bad FCS!\n";
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (!parsedPacket->ieee80211Header->isDataFrame()) {
    // we only process data frames
    std::cerr << "Got packet that is not a data packet" << (int) parsedPacket->ieee80211Header->getFrameControl()
              << "\n";
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->ieee80211Header->getRadioPort() != options.radio_port) {
    // If we have the proper filter on pcap only packets with the right radiotap port should pass through
    std::cerr << "Got packet with wrong radio port " << (int) parsedPacket->ieee80211Header->getRadioPort() << "\n";
    //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
    wb_rx_stats.count_p_bad++;
    return;
  }
  // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
  if (parsedPacket->payloadSize <= 0) {
    std::cerr << "Discarding packet due to no actual payload !\n";
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    std::cerr << "Discarding packet due to payload exceeding max " << (int) parsedPacket->payloadSize << "\n";
    wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->allAntennaValues.size() > MAX_N_ANTENNAS_PER_WIFI_CARD) {
    std::cerr << "Wifi card with " << parsedPacket->allAntennaValues.size() << " antennas\n";
  }
  if(WLAN_IDX<rssiForWifiCard.size()){
    auto &thisWifiCard = rssiForWifiCard.at(WLAN_IDX);
    std::cout<<all_rssi_to_string(parsedPacket->allAntennaValues);
    const auto best_rssi=RawReceiverHelper::get_best_rssi_of_card(parsedPacket->allAntennaValues);
    if(best_rssi!=0){
      thisWifiCard.addRSSI(best_rssi);
    }
    /*for (const auto &value: parsedPacket->allAntennaValues) {
      // don't care from which antenna the value came
      // There seems to be a bug where sometimes the reported rssi is 0 ???!!
      if(value.rssi!=0){
        thisWifiCard.addRSSI(value.rssi);
      }
    }*/
  }else{
    std::cerr<<"Ehm wlan idx out of bounds\n";
  }

  //RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
  //const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
  //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
  //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
  //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";
  //parsedPacket->ieee80211Header->printSequenceControl();
  //mSeqNrCounter.onNewPacket(*parsedPacket->ieee80211Header);


  // now to the actual payload
  const uint8_t *packetPayload = parsedPacket->payload;
  const size_t packetPayloadSize = parsedPacket->payloadSize;

  if (packetPayload[0] == WFB_PACKET_KEY) {
    if (packetPayloadSize != WBSessionKeyPacket::SIZE_BYTES) {
      std::cerr << "invalid session key packet\n";
      wb_rx_stats.count_p_bad++;
      return;
    }
    WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
    if (mDecryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
      std::cout << "Initializing new session. IS_FEC_ENABLED:" << (int) sessionKeyPacket.IS_FEC_ENABLED
                << " MAX_N_FRAGMENTS_PER_BLOCK:" << (int) sessionKeyPacket.MAX_N_FRAGMENTS_PER_BLOCK << "\n";
      // We got a new session key (aka a session key that has not been received yet)
      wb_rx_stats.count_p_decryption_ok++;
      IS_FEC_ENABLED = sessionKeyPacket.IS_FEC_ENABLED;
      auto callback = [this](const uint8_t *payload, std::size_t payloadSize) {
        if (mOutputDataCallback != nullptr) {
          mOutputDataCallback(payload, payloadSize);
        } else {
          std::cerr << "No data callback registered\n";
        }
      };
      if (IS_FEC_ENABLED) {
        mFECDDecoder = std::make_unique<FECDecoder>((unsigned int) sessionKeyPacket.MAX_N_FRAGMENTS_PER_BLOCK);
        mFECDDecoder->mSendDecodedPayloadCallback = callback;
      } else {
        mFECDisabledDecoder = std::make_unique<FECDisabledDecoder>();
        mFECDisabledDecoder->mSendDecodedPayloadCallback = callback;
      }
    } else {
      wb_rx_stats.count_p_decryption_ok++;
    }
    return;
  } else if (packetPayload[0] == WFB_PACKET_DATA) {
    if (packetPayloadSize < sizeof(WBDataHeader) + sizeof(FECPayloadHdr)) {
      std::cerr << "Too short packet (fec header missing)\n";
      wb_rx_stats.count_p_bad++;
      return;
    }
    const WBDataHeader &wbDataHeader = *((WBDataHeader *) packetPayload);
    assert(wbDataHeader.packet_type == WFB_PACKET_DATA);
    wb_rx_stats.count_bytes_data_received+=packetPayloadSize;

    const auto decryptedPayload = mDecryptor.decryptPacket(wbDataHeader.nonce, packetPayload + sizeof(WBDataHeader),
                                                           packetPayloadSize - sizeof(WBDataHeader), wbDataHeader);
    if (decryptedPayload == std::nullopt) {
      //std::cerr << "unable to decrypt packet :" << std::to_string(wbDataHeader.nonce) << "\n";
      wb_rx_stats.count_p_decryption_err++;
      return;
    }

    wb_rx_stats.count_p_decryption_ok++;

    assert(decryptedPayload->size() <= FEC_MAX_PACKET_SIZE);
    if (IS_FEC_ENABLED) {
      if (!mFECDDecoder) {
        std::cout << "FEC K,N is not set yet\n";
        return;
      }
      if (!mFECDDecoder->validateAndProcessPacket(wbDataHeader.nonce, *decryptedPayload)) {
        wb_rx_stats.count_p_bad++;
      }
    } else {
      if (!mFECDisabledDecoder) {
        std::cout << "FEC K,N is not set yet(disabled)\n";
        return;
      }
      mFECDisabledDecoder->processRawDataBlockFecDisabled(wbDataHeader.nonce, *decryptedPayload);
    }
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
    else if(payload[0]==WFB_PACKET_LATENCY_BEACON){
        // for testing only. It won't work if the tx and rx are running on different systems
            assert(payloadSize==sizeof(LatencyTestingPacket));
            const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)payload;
            const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
            const auto latency=std::chrono::steady_clock::now()-timestamp;
            //std::cout<<"Packet latency on this system is "<<std::chrono::duration_cast<std::chrono::nanoseconds>(latency).count()<<"\n";
            avgLatencyBeaconPacketLatency.add(latency);
    }
#endif
  else {
    std::cerr << "Unknown packet type " << (int) packetPayload[0] << " \n";
    wb_rx_stats.count_p_bad += 1;
    return;
  }
}
