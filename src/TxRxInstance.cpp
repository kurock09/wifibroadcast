//
// Created by consti10 on 27.06.23.
//

#include "TxRxInstance.h"

#include <utility>

#include "RawReceiver.hpp"

TxRxInstance::TxRxInstance(std::vector<std::string> wifi_cards,Options options1)
    : m_options(options1),
      m_wifi_cards(std::move(wifi_cards)),
      m_radiotap_header(RadiotapHeader::UserSelectableParams{})
{
  m_console=wifibroadcast::log::create_or_get("WBTxRx");
  assert(!m_wifi_cards.empty());
  m_receive_pollfds.resize(m_wifi_cards.size());
  m_rx_packet_stats.resize(m_wifi_cards.size());
  for(int i=0;i<m_wifi_cards.size();i++){
    auto wifi_card=m_wifi_cards[i];
    PcapTxRx pcapTxRx{};
    pcapTxRx.tx=RawReceiverHelper::helper_open_pcap_rx(wifi_card);
    pcapTxRx.rx=RawTransmitterHelper::openTxWithPcap(wifi_card);
    //pcap_setdirection(pcapTxRx.rx, PCAP_D_IN);
    m_pcap_handles.push_back(pcapTxRx);
    auto fd = pcap_get_selectable_fd(pcapTxRx.rx);
    m_receive_pollfds[i].fd = fd;
    m_receive_pollfds[i].events = POLLIN;
  }
  m_encryptor=std::make_unique<Encryptor>(std::nullopt);
  m_decryptor=std::make_unique<Decryptor>(std::nullopt);
  m_encryptor->makeNewSessionKey(m_tx_sess_key_packet.sessionKeyNonce,
                                m_tx_sess_key_packet.sessionKeyData);
  // next session key in delta ms if packets are being fed
  m_session_key_announce_ts = std::chrono::steady_clock::now()+SESSION_KEY_ANNOUNCE_DELTA;
}

TxRxInstance::~TxRxInstance() {
  stop_receiving();
  for(auto& fd: m_receive_pollfds){
    close(fd.fd);
  }
  for(auto& pcapTxRx:m_pcap_handles){
    pcap_close(pcapTxRx.rx);
    pcap_close(pcapTxRx.tx);
  }
}

void TxRxInstance::tx_inject_packet(const uint8_t radioPort,
                                    const uint8_t* data, int data_len) {
  std::lock_guard<std::mutex> guard(m_tx_mutex);
  // new wifi packet
  auto packet_size=
      // Radiotap header comes first
      RadiotapHeader::SIZE_BYTES+
      // Then the Ieee80211 header
      Ieee80211Header::SIZE_BYTES+
      // after that, the nonce (sequence number)
      sizeof(uint64_t)+
      // actual data
      data_len+
      // encryption suffix
      crypto_aead_chacha20poly1305_ABYTES;
  std::vector<uint8_t> packet = std::vector<uint8_t>(packet_size);
  uint8_t* packet_buff=packet.data();
  // radiotap header comes first
  memcpy(packet_buff, m_radiotap_header.getData(), RadiotapHeader::SIZE_BYTES);
  // Iee80211 header comes next
  mIeee80211Header.writeParams(radioPort,m_ieee80211_seq);
  memcpy(packet_buff+RadiotapHeader::SIZE_BYTES,mIeee80211Header.getData(),Ieee80211Header::SIZE_BYTES);
  m_ieee80211_seq++;
  // create a new nonce
  uint64_t nonce=++m_nonce;
  // copy over the nonce and fill with the rest of the packet with the encrypted data
  memcpy(packet_buff+RadiotapHeader::SIZE_BYTES+Ieee80211Header::SIZE_BYTES,(uint8_t*)&nonce,sizeof(uint64_t));
  uint8_t* encrypted_data_p=packet_buff+RadiotapHeader::SIZE_BYTES+Ieee80211Header::SIZE_BYTES+sizeof(uint64_t);
  const auto ciphertext_len=m_encryptor->encrypt2(m_nonce,data,data_len,encrypted_data_p);
  // we allocate the right size in the beginning, but check if ciphertext_len is actually matching what we calculated
  // (the documentation says 'write up to n bytes' but they probably mean (write exactly n bytes unless an error occurs)
  assert(data_len+crypto_aead_chacha20poly1305_ABYTES == ciphertext_len);
  // inject via pcap
  // we inject the packet on whatever card has the highest rx rssi right now
  pcap_t *tx= m_pcap_handles[m_highest_rssi_index].tx;
  const auto len_injected=pcap_inject(tx, packet.data(), packet.size());
  if (len_injected != (int) packet.size()) {
    // This basically should never fail - if the tx queue is full, pcap seems to wait ?!
    wifibroadcast::log::get_default()->warn("pcap -unable to inject packet size:{} ret:{} err:{}",packet.size(),len_injected, pcap_geterr(tx));
  }
  announce_session_key_if_needed();
}

void TxRxInstance::rx_register_callback(TxRxInstance::OUTPUT_DATA_CALLBACK cb) {
  m_output_cb=std::move(cb);
}

void TxRxInstance::rx_register_specific_cb(const uint8_t radioPort,TxRxInstance::SPECIFIC_OUTPUT_DATA_CB cb) {
  m_specific_callbacks[radioPort]=std::move(cb);
}

void TxRxInstance::set_extended_debugging(bool enable_debug_tx,bool enable_debug_rx) {
  m_advanced_debugging_tx = enable_debug_tx;
  m_advanced_debugging_rx =enable_debug_rx;
}

void TxRxInstance::loop_receive_packets() {
  while (keep_receiving){
    const int timeoutMS = (int) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(1)).count();
    int rc = poll(m_receive_pollfds.data(), m_receive_pollfds.size(), timeoutMS);

    if (rc < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      wifibroadcast::log::get_default()->warn("Poll error: {}", strerror(errno));
    }

    if (rc == 0) {
      // timeout expired
      m_console->debug("Timeout");
      continue;
    }
    // TODO Optimization: If rc>1 we have data on more than one wifi card. It would be better to alternating process a couple of packets from card 1, then card 2 or similar
    for (int i = 0; rc > 0 && i < m_receive_pollfds.size(); i++) {
      //m_console->debug("Got data on {}",i);
      if (m_receive_pollfds[i].revents & (POLLERR | POLLNVAL)) {
        if(keep_receiving){
          // we should only get errors here if the card is disconnected
          m_n_receiver_errors++;
          // limit logging here
          const auto elapsed=std::chrono::steady_clock::now()-m_last_receiver_error_log;
          if(elapsed>std::chrono::seconds(1)){
            wifibroadcast::log::get_default()->warn("RawReceiver errors {} on pcap fds {} (wlan {})",m_n_receiver_errors,i,m_wifi_cards[i]);
            m_last_receiver_error_log=std::chrono::steady_clock::now();
          }
        }else{
          return;
        }
      }
      if (m_receive_pollfds[i].revents & POLLIN) {
        loop_iter(i);
        rc -= 1;
      }
    }

  }
}

int TxRxInstance::loop_iter(int rx_index) {
  pcap_t* ppcap=m_pcap_handles[rx_index].rx;
  // loop while incoming queue is not empty
  int nPacketsPolledUntilQueueWasEmpty = 0;
  for (;;) {
    struct pcap_pkthdr hdr{};
    const uint8_t *pkt = pcap_next(ppcap, &hdr);
    if (pkt == nullptr) {
#ifdef ENABLE_ADVANCED_DEBUGGING
      nOfPacketsPolledFromPcapQueuePerIteration.add(nPacketsPolledUntilQueueWasEmpty);
      wifibroadcast::log::get_default()->debug("nOfPacketsPolledFromPcapQueuePerIteration: {}",nOfPacketsPolledFromPcapQueuePerIteration.getAvgReadable());
      nOfPacketsPolledFromPcapQueuePerIteration.reset();
#endif
      break;
    }
    on_new_packet(rx_index,hdr,pkt);
#ifdef ENABLE_ADVANCED_DEBUGGING
    // how long the cpu spends on agg.processPacket
    timeForParsingPackets.printInIntervalls(std::chrono::seconds(1));
#endif
    nPacketsPolledUntilQueueWasEmpty++;
  }
  return nPacketsPolledUntilQueueWasEmpty;
}

void TxRxInstance::on_new_packet(const uint8_t wlan_idx, const pcap_pkthdr &hdr,
                                 const uint8_t *pkt) {
  m_rx_packet_stats[wlan_idx].count_received_packets++;
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt, m_options.rtl8812au_rssi_fixup);
  const uint8_t *pkt_payload = parsedPacket->payload;
  const size_t pkt_payload_size = parsedPacket->payloadSize;

  if (parsedPacket == std::nullopt) {
    if(m_advanced_debugging_rx){
      m_console->warn("Discarding packet due to pcap parsing error!");
    }
    return;
  }
  if (parsedPacket->frameFailedFCSCheck) {
    if(m_advanced_debugging_rx){
      m_console->debug("Discarding packet due to bad FCS!");
    }
    return;
  }
  if (!parsedPacket->ieee80211Header->isDataFrame()) {
    if(m_advanced_debugging_rx){
      // we only process data frames
      m_console->debug("Got packet that is not a data packet {}",(int) parsedPacket->ieee80211Header->getFrameControl());
    }
    return;
  }
  // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
  if (parsedPacket->payloadSize <= 0) {
    m_console->warn("Discarding packet due to no actual payload !");
    return;
  }
  if (parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    m_console->warn("Discarding packet due to payload exceeding max {}",(int) parsedPacket->payloadSize);
    return;
  }
  const auto radio_port=parsedPacket->ieee80211Header->getRadioPort();
  m_console->debug("Got packet raio port {}",radio_port);
  if(radio_port==RADIO_PORT_SESSION_KEY_PACKETS){
    if (pkt_payload_size != WBSessionKeyPacket::SIZE_BYTES) {
      if(m_advanced_debugging_rx){
        m_console->warn("Cannot be session key packet - size mismatch {}",pkt_payload_size);
      }
      return;
    }
    WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
    if (m_decryptor->onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
      m_console->debug("Initializing new session.");
    }
  }else{
    // the payload needs to include at least the nonce, the encryption suffix and 1 byte of actual payload
    static constexpr auto MIN_PACKET_PAYLOAD_SIZE=sizeof(uint64_t)+crypto_aead_chacha20poly1305_ABYTES+1;
    if(pkt_payload_size<MIN_PACKET_PAYLOAD_SIZE){
      if(m_advanced_debugging_rx){
        m_console->debug("Got packet with payload of {} (min:{})",pkt_payload_size,MIN_PACKET_PAYLOAD_SIZE);
      }
      return ;
    }
    const bool valid=process_received_data_packet(wlan_idx,radio_port,pkt_payload,pkt_payload_size);
    if(valid){
      // We only use known "good" packets for those stats.
      auto &this_wifi_card_stats = m_rx_packet_stats.at(wlan_idx);
      auto& rssi_for_this_card=this_wifi_card_stats.rssi_for_wifi_card;
      //m_console->debug("{}",all_rssi_to_string(parsedPacket->allAntennaValues));
      const auto best_rssi=RawReceiverHelper::get_best_rssi_of_card(parsedPacket->allAntennaValues);
      //m_console->debug("best_rssi:{}",(int)best_rssi);
      if(best_rssi.has_value()){
        rssi_for_this_card.addRSSI(best_rssi.value());
      }
      this_wifi_card_stats.count_received_packets++;
      if(parsedPacket->mcs_index.has_value()){
        m_rx_stats.last_received_packet_mcs_index=parsedPacket->mcs_index.value();
      }
      if(parsedPacket->channel_width.has_value()){
        m_rx_stats.last_received_packet_channel_width=parsedPacket->channel_width.value();
      }
    }
  }
}

bool TxRxInstance::process_received_data_packet(int wlan_idx,uint8_t radio_port,const uint8_t *pkt_payload,const size_t pkt_payload_size) {
  std::shared_ptr<std::vector<uint8_t>> decrypted=std::make_shared<std::vector<uint8_t>>(pkt_payload_size-sizeof(uint64_t)-crypto_aead_chacha20poly1305_ABYTES);
  // nonce comes first
  auto* nonce_p=(uint64_t*) pkt_payload;
  uint64_t nonce=*nonce_p;
  // after that, we have the encrypted data (and the encryption suffix)
  const uint8_t* encrypted_data_with_suffix=pkt_payload+sizeof(uint64_t);
  const auto encrypted_data_with_suffix_len = pkt_payload_size-sizeof(uint64_t);
  const auto res=m_decryptor->decrypt2(nonce,encrypted_data_with_suffix,encrypted_data_with_suffix_len,
                                         decrypted->data(),decrypted->size());
  if(res!=-1){
    on_valid_packet(nonce,wlan_idx,radio_port,decrypted->data(),decrypted->size());
    m_rx_packet_stats[wlan_idx].count_valid_packets++;
    if(wlan_idx==0){
      uint16_t tmp=nonce;
      m_seq_nr_helper.on_new_sequence_number(tmp);
      m_console->debug("packet loss:{}",m_seq_nr_helper.get_current_loss_percent());
    }
    return true;
  }
  m_console->debug("Got non-wb packet {}",radio_port);
  return false;
}

void TxRxInstance::on_valid_packet(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len) {
  bool forwarded= false;
  if(m_output_cb!= nullptr){
    m_output_cb(nonce,wlan_index,radioPort,data,data_len);
    forwarded= true;
  }
  // find a consumer for data of this radio port
  auto specific=m_specific_callbacks.find(radioPort);
  if(specific!=m_specific_callbacks.end()){
    SPECIFIC_OUTPUT_DATA_CB specific_cb=specific->second;
    specific_cb(nonce,wlan_index,data,data_len);
    forwarded= true;
  }
  if(!forwarded){
    m_console->debug("Got valid packet nonce:{} wlan_idx:{} radio_port:{} size:{}",nonce,wlan_index,radioPort,data_len);
  }
}

void TxRxInstance::start_receiving() {
  keep_receiving= true;
  m_receive_thread=std::make_unique<std::thread>([this](){
    loop_receive_packets();
  });
}

void TxRxInstance::stop_receiving() {
  keep_receiving= false;
  if(m_receive_thread!= nullptr){
    if(m_receive_thread->joinable()){
      m_receive_thread->join();
    }
    m_receive_thread= nullptr;
  }
}

void TxRxInstance::announce_session_key_if_needed() {
  const auto cur_ts = std::chrono::steady_clock::now();
  if (cur_ts >= m_session_key_announce_ts) {
    // Announce session key
    send_session_key();
    m_session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
  }
}

void TxRxInstance::send_session_key() {
  AbstractWBPacket tmp{(uint8_t *)&m_tx_sess_key_packet, WBSessionKeyPacket::SIZE_BYTES};
  Ieee80211Header tmp_hdr=mIeee80211Header;
  tmp_hdr.writeParams(RADIO_PORT_SESSION_KEY_PACKETS,0);
  auto session_key_packet=RawTransmitterHelper::createRadiotapPacket(m_radiotap_header,tmp_hdr,tmp);
  pcap_t *tx= m_pcap_handles[m_highest_rssi_index].tx;
  const auto len_injected=pcap_inject(tx, session_key_packet.data(),session_key_packet.size());
  if (len_injected != (int) session_key_packet.size()) {
    // This basically should never fail - if the tx queue is full, pcap seems to wait ?!
    wifibroadcast::log::get_default()->warn("pcap -unable to inject session key packet size:{} ret:{} err:{}",session_key_packet.size(),len_injected, pcap_geterr(tx));
  }
}

void TxRxInstance::tx_update_mcs_index(uint8_t mcs_index) {
  m_console->debug("update_mcs_index {}",mcs_index);
  m_radioTapHeaderParams.mcs_index=mcs_index;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void TxRxInstance::tx_update_channel_width(int width_mhz) {
  m_console->debug("update_channel_width {}",width_mhz);
  m_radioTapHeaderParams.bandwidth=width_mhz;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void TxRxInstance::tx_update_stbc(int stbc) {
  m_console->debug("update_stbc {}",stbc);
  if(stbc<0 || stbc> 3){
    m_console->warn("Invalid stbc index");
    return ;
  }
  m_radioTapHeaderParams.stbc=stbc;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void TxRxInstance::tx_update_guard_interval(bool short_gi) {
  m_radioTapHeaderParams.short_gi=short_gi;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void TxRxInstance::tx_update_ldpc(bool ldpc) {
  m_radioTapHeaderParams.ldpc=ldpc;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void TxRxInstance::tx_threadsafe_update_radiotap_header(const RadiotapHeader::UserSelectableParams &params) {
  auto newRadioTapHeader=RadiotapHeader{params};
  m_radiotap_header =newRadioTapHeader;
}
TxRxInstance::RxStats TxRxInstance::get_rx_stats() {
  return TxRxInstance::RxStats();
}

TxRxInstance::RxStatsPerCard TxRxInstance::get_rx_stats_for_card(int card_index) {
  return TxRxInstance::RxStatsPerCard();
}
