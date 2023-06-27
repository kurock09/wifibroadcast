//
// Created by consti10 on 27.06.23.
//

#include "TxRxInstance.h"

#include <utility>

#include "RawReceiver.hpp"

TxRxInstance::TxRxInstance(std::vector<std::string> wifi_cards)
    : m_wifi_cards(std::move(wifi_cards)),
      m_radiotap_header(RadiotapHeader::UserSelectableParams{})
{
  m_console=wifibroadcast::log::create_or_get("WBTxRx");
  assert(!m_wifi_cards.empty());
  mReceiverFDs.resize(m_wifi_cards.size());
  m_rx_packet_stats.resize(m_wifi_cards.size());
  for(int i=0;i<m_wifi_cards.size();i++){
    auto wifi_card=m_wifi_cards[i];
    PcapTxRx pcapTxRx{};
    pcapTxRx.tx=RawReceiverHelper::helper_open_pcap_rx(wifi_card);
    pcapTxRx.rx=RawTransmitterHelper::openTxWithPcap(wifi_card);
    //pcap_setdirection(pcapTxRx.rx, PCAP_D_IN);
    m_pcap_handles.push_back(pcapTxRx);
    auto fd = pcap_get_selectable_fd(pcapTxRx.rx);
    mReceiverFDs[i].fd = fd;
    mReceiverFDs[i].events = POLLIN;
  }
  m_encryptor=std::make_unique<Encryptor>(std::nullopt);
  m_decryptor=std::make_unique<Decryptor>(std::nullopt);
  m_encryptor->makeNewSessionKey(m_tx_sess_key_packet.sessionKeyNonce,
                                m_tx_sess_key_packet.sessionKeyData);
  // next session key in delta ms if packets are being fed
  m_session_key_announce_ts = std::chrono::steady_clock::now()+SESSION_KEY_ANNOUNCE_DELTA;
}

void TxRxInstance::tx_inject_packet(const uint8_t radioPort,
                                    const uint8_t* data, int data_len) {
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
  mIeee80211Header.writeParams(radioPort,0);
  memcpy(packet_buff+RadiotapHeader::SIZE_BYTES,mIeee80211Header.getData(),Ieee80211Header::SIZE_BYTES);
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

void TxRxInstance::loop_receive_packets() {
  while (true){
    const int timeoutMS = (int) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(1)).count();
    int rc = poll(mReceiverFDs.data(), mReceiverFDs.size(), timeoutMS);

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
    for (int i = 0; rc > 0 && i < mReceiverFDs.size(); i++) {
      //m_console->debug("Got data on {}",i);
      if (mReceiverFDs[i].revents & (POLLERR | POLLNVAL)) {
        if(keep_running){
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
      if (mReceiverFDs[i].revents & POLLIN) {
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
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt, true);
  const uint8_t *pkt_payload = parsedPacket->payload;
  const size_t pkt_payload_size = parsedPacket->payloadSize;

  if(!parsedPacket->ieee80211Header->isDataFrame()){
    return ;
  }
  const auto radio_port=parsedPacket->ieee80211Header->getRadioPort();
  m_console->debug("Got packet raio port {}",radio_port);
  if(radio_port==RADIO_PORT_SESSION_KEY_PACKETS){
    if (pkt_payload_size != WBSessionKeyPacket::SIZE_BYTES) {
      m_console->warn("invalid session key packet - size mismatch");
      return;
    }
    WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
    if (m_decryptor->onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
      m_console->debug("Initializing new session.");
    }
  }else{
    process_received_data_packet(wlan_idx,radio_port,pkt_payload,pkt_payload_size);
  }
}


void TxRxInstance::process_received_data_packet(int wlan_idx,uint8_t radio_port,
                                                const uint8_t *pkt_payload,
                                                const size_t pkt_payload_size) {
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
  }else{
    m_console->debug("Got non-wb packet {}",radio_port);
  }
}

void TxRxInstance::on_valid_packet(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len) {
  if(m_output_cb!= nullptr){
    m_output_cb(nonce,wlan_index,radioPort,data,data_len);
  }else{
    m_console->debug("Got valid packet nonce:{} wlan_idx:{} radio_port:{} size:{}",nonce,wlan_index,radioPort,data_len);
  }
}

void TxRxInstance::start_receiving() {
  m_receive_thread=std::make_unique<std::thread>([this](){
    loop_receive_packets();
  });
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
