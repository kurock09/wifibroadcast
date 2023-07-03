//
// Created by consti10 on 27.06.23.
//

#include "WBTxRx.h"

#include <utility>

#include "pcap_helper.hpp"
#include "SchedulingHelper.hpp"

WBTxRx::WBTxRx(std::vector<std::string> wifi_cards,Options options1)
    : m_options(options1),
      m_wifi_cards(std::move(wifi_cards)),
      m_radiotap_header(RadiotapHeader::UserSelectableParams{})
{
  assert(!m_wifi_cards.empty());
  m_console=wifibroadcast::log::create_or_get("WBTxRx");
  m_console->debug(" cards:{} set_direction:{}",StringHelper::string_vec_as_string(m_wifi_cards),m_options.set_direction);
  m_receive_pollfds.resize(m_wifi_cards.size());
  m_rx_stats_per_card.resize(m_wifi_cards.size());
  for(int i=0;i<m_wifi_cards.size();i++){
    auto tmp=std::make_shared<seq_nr::Helper>();
    m_seq_nr_per_card.push_back(tmp);
  }
  for(int i=0;i<m_wifi_cards.size();i++){
    auto wifi_card=m_wifi_cards[i];
    PcapTxRx pcapTxRx{};
    pcapTxRx.rx=wifibroadcast::pcap_helper::open_pcap_rx(wifi_card);
    //pcapTxRx.tx=wifibroadcast::pcap_helper::open_pcap_tx(wifi_card);
    if(m_options.set_direction){
      pcap_setdirection(pcapTxRx.rx, PCAP_D_IN);
    }
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

WBTxRx::~WBTxRx() {
  stop_receiving();
  for(auto& fd: m_receive_pollfds){
    close(fd.fd);
  }
  for(auto& pcapTxRx:m_pcap_handles){
    pcap_close(pcapTxRx.rx);
    //pcap_close(pcapTxRx.tx);
  }
}

void WBTxRx::tx_inject_packet(const uint8_t radioPort,
                                    const uint8_t* data, int data_len) {
  assert(data_len<=MAX_PACKET_PAYLOAD_SIZE);
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
  pcap_t *tx= m_pcap_handles[m_curr_tx_card].rx;
  const auto before_injection = std::chrono::steady_clock::now();
  //const auto len_injected=pcap_inject(tx, packet.data(), packet.size());
  const auto len_injected=write(m_receive_pollfds.at(0).fd,packet.data(),packet.size());
  const auto delta_inject=std::chrono::steady_clock::now()-before_injection;
  if(delta_inject>=MAX_SANE_INJECTION_TIME){
    m_tx_stats.count_tx_injections_error_hint++;
  }
  if (len_injected != (int) packet.size()) {
    // This basically should never fail - if the tx queue is full, pcap seems to wait ?!
    m_console->warn("pcap -unable to inject packet size:{} ret:{} err:[{}]",packet.size(),len_injected, pcap_geterr(tx));
  }else{
    m_tx_stats.n_injected_bytes+=packet_size;
    m_tx_stats.n_injected_packets++;
  }
  announce_session_key_if_needed();
}

void WBTxRx::rx_register_callback(WBTxRx::OUTPUT_DATA_CALLBACK cb) {
  m_output_cb=std::move(cb);
}

void WBTxRx::rx_register_stream_handler(std::shared_ptr<StreamRxHandler> handler) {
  assert(handler);
  m_rx_handlers[handler->radio_port]=handler;
}

void WBTxRx::rx_unregister_stream_handler(uint8_t radio_port) {
  m_rx_handlers.erase(radio_port);
}

void WBTxRx::loop_receive_packets() {
  if(m_options.receive_thread_max_realtime){
    SchedulingHelper::setThreadParamsMaxRealtime();
  }
  while (keep_receiving){
    const int timeoutMS = (int) std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(1)).count();
    int rc = poll(m_receive_pollfds.data(), m_receive_pollfds.size(), timeoutMS);

    if (rc < 0) {
      if (errno == EINTR || errno == EAGAIN) continue;
      m_console->warn("Poll error: {}", strerror(errno));
    }

    if (rc == 0) {
      // timeout expired
      if(m_options.advanced_debugging_rx){
        m_console->debug("Timeout - no packet after 1 second");
      }
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
            m_console->warn("RawReceiver errors {} on pcap fds {} (wlan {})",m_n_receiver_errors,i,m_wifi_cards[i]);
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

int WBTxRx::loop_iter(int rx_index) {
  pcap_t* ppcap=m_pcap_handles[rx_index].rx;
  // loop while incoming queue is not empty
  int nPacketsPolledUntilQueueWasEmpty = 0;
  for (;;) {
    struct pcap_pkthdr hdr{};
    const uint8_t *pkt = pcap_next(ppcap, &hdr);
    if (pkt == nullptr) {
      if(m_options.advanced_latency_debugging_rx){
        m_n_packets_polled_pcap.add(nPacketsPolledUntilQueueWasEmpty);
        if(m_n_packets_polled_pcap.get_delta_since_last_reset()>std::chrono::seconds(1)){
          m_console->debug("m_n_packets_polled_pcap: {}",m_n_packets_polled_pcap.getAvgReadable());
          m_n_packets_polled_pcap.reset();
        }
      }
      break;
    }
    if(m_options.advanced_latency_debugging_rx){
      const auto delta=std::chrono::system_clock::now()-MyTimeHelper::to_time_point_system_clock(hdr.ts);
      m_packet_host_latency.add(delta);
      if(m_packet_host_latency.get_delta_since_last_reset()>std::chrono::seconds(1)){
        m_console->debug("packet latency {}",m_packet_host_latency.getAvgReadable());
        m_packet_host_latency.reset();
      }
    }
    on_new_packet(rx_index,hdr,pkt);
    nPacketsPolledUntilQueueWasEmpty++;
  }
  return nPacketsPolledUntilQueueWasEmpty;
}

void WBTxRx::on_new_packet(const uint8_t wlan_idx, const pcap_pkthdr &hdr,
                                 const uint8_t *pkt) {
  if(m_options.log_all_received_packets){
    m_console->debug("Got packet {} {}",wlan_idx,hdr.len);
  }
  const auto parsedPacket = wifibroadcast::pcap_helper::processReceivedPcapPacket(hdr, pkt, m_options.rtl8812au_rssi_fixup);
  if (parsedPacket == std::nullopt) {
    if(m_options.advanced_debugging_rx){
      m_console->warn("Discarding packet due to pcap parsing error!");
    }
    return;
  }
  const uint8_t *pkt_payload = parsedPacket->payload;
  const size_t pkt_payload_size = parsedPacket->payloadSize;
  m_rx_stats.count_p_any++;
  m_rx_stats.count_bytes_any+=pkt_payload_size;
  m_rx_stats_per_card[wlan_idx].count_p_any++;

  if (parsedPacket->frameFailedFCSCheck) {
    if(m_options.advanced_debugging_rx){
      m_console->debug("Discarding packet due to bad FCS!");
    }
    return;
  }
  if (!parsedPacket->ieee80211Header->isDataFrame()) {
    if(m_options.advanced_debugging_rx){
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
  if(radio_port==RADIO_PORT_SESSION_KEY_PACKETS){
    if (pkt_payload_size != sizeof(SessionKeyPacket)) {
      if(m_options.advanced_debugging_rx){
        m_console->warn("Cannot be session key packet - size mismatch {}",pkt_payload_size);
      }
      return;
    }
    // Issue when using multiple wifi card(s) on ground - by example:
    // When we inject data on card 1, it is intended for the "air unit" - however,
    // card 2 on the ground likely picks up such a packet and if we were not to ignore it, we'd get the session key
    // TODO make it better -
    // for now, ignore session key packets not from card 0
    if(wlan_idx!=0){
      return ;
    }
    SessionKeyPacket &sessionKeyPacket = *((SessionKeyPacket*) parsedPacket->payload);
    if (m_decryptor->onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
      m_console->debug("Initializing new session.");
      m_rx_stats.n_received_valid_session_key_packets++;
      for(auto& handler:m_rx_handlers){
        auto opt_cb_session=handler.second->cb_session;
        if(opt_cb_session){
          opt_cb_session();
        }
      }
    }
  }else{
    // the payload needs to include at least the nonce, the encryption suffix and 1 byte of actual payload
    static constexpr auto MIN_PACKET_PAYLOAD_SIZE=sizeof(uint64_t)+crypto_aead_chacha20poly1305_ABYTES+1;
    if(pkt_payload_size<MIN_PACKET_PAYLOAD_SIZE){
      if(m_options.advanced_debugging_rx){
        m_console->debug("Got packet with payload of {} (min:{})",pkt_payload_size,MIN_PACKET_PAYLOAD_SIZE);
      }
      return ;
    }
    const bool valid=process_received_data_packet(wlan_idx,radio_port,pkt_payload,pkt_payload_size);
    if(valid){
      m_rx_stats.count_p_valid++;
      m_rx_stats.count_bytes_valid+=pkt_payload_size;
      // We only use known "good" packets for those stats.
      auto &this_wifi_card_stats = m_rx_stats_per_card.at(wlan_idx);
      auto& rssi_for_this_card=this_wifi_card_stats.rssi_for_wifi_card;
      //m_console->debug("{}",all_rssi_to_string(parsedPacket->allAntennaValues));
      const auto best_rssi=wifibroadcast::pcap_helper::get_best_rssi_of_card(parsedPacket->allAntennaValues);
      //m_console->debug("best_rssi:{}",(int)best_rssi);
      if(best_rssi.has_value()){
        rssi_for_this_card.addRSSI(best_rssi.value());
      }
      this_wifi_card_stats.count_p_valid++;
      if(parsedPacket->mcs_index.has_value()){
        m_rx_stats.last_received_packet_mcs_index=parsedPacket->mcs_index.value();
      }
      if(parsedPacket->channel_width.has_value()){
        m_rx_stats.last_received_packet_channel_width=parsedPacket->channel_width.value();
      }
      // Adjustment of which card is used for injecting packets in case there are multiple RX card(s)
      if(m_wifi_cards.size()>1){
        const auto elapsed=std::chrono::steady_clock::now()-m_last_highest_rssi_adjustment_tp;
        if(elapsed>=HIGHEST_RSSI_ADJUSTMENT_INTERVAL){
          m_last_highest_rssi_adjustment_tp=std::chrono::steady_clock::now();
          int idx_card_highest_rssi=0;
          int highest_dbm=-1000;
          for(int i=0;i< m_rx_stats_per_card.size();i++){
            const int dbm_average=
                m_rx_stats_per_card.at(i).rssi_for_wifi_card.getAverage();
            m_rx_stats_per_card.at(i).rssi_for_wifi_card.reset();
            if(dbm_average>highest_dbm){
              idx_card_highest_rssi=i;
              highest_dbm=dbm_average;
            }
            m_console->debug("Card {} dbm_average:{}",i,dbm_average);
          }
          if(m_curr_tx_card!=idx_card_highest_rssi){
            // TODO
            // to avoid switching too often, only switch if the difference in dBm exceeds a threshold value
            m_console->debug("Switching to card {}",idx_card_highest_rssi);
            m_curr_tx_card=idx_card_highest_rssi;
          }
        }
      }
    }
  }
}

bool WBTxRx::process_received_data_packet(int wlan_idx,uint8_t radio_port,const uint8_t *pkt_payload,const size_t pkt_payload_size) {
  std::shared_ptr<std::vector<uint8_t>> decrypted=std::make_shared<std::vector<uint8_t>>(pkt_payload_size-sizeof(uint64_t)-crypto_aead_chacha20poly1305_ABYTES);
  // nonce comes first
  auto* nonce_p=(uint64_t*) pkt_payload;
  uint64_t nonce=*nonce_p;
  // after that, we have the encrypted data (and the encryption suffix)
  const uint8_t* encrypted_data_with_suffix=pkt_payload+sizeof(uint64_t);
  const auto encrypted_data_with_suffix_len = pkt_payload_size-sizeof(uint64_t);
  const auto res=m_decryptor->decrypt2(nonce,encrypted_data_with_suffix,encrypted_data_with_suffix_len,
                                         decrypted->data());
  if(res!=-1){
    if(m_options.log_all_received_validated_packets){
      m_console->debug("Got valid packet nonce:{} wlan_idx:{} radio_port:{} size:{}",nonce,wlan_idx,radio_port,pkt_payload_size);
    }
    on_valid_packet(nonce,wlan_idx,radio_port,decrypted->data(),decrypted->size());
    if(wlan_idx==0){
      uint16_t tmp=nonce;
      m_seq_nr_helper.on_new_sequence_number(tmp);
      m_rx_stats.curr_packet_loss=m_seq_nr_helper.get_current_loss_percent();
      //m_console->debug("packet loss:{}",m_seq_nr_helper.get_current_loss_percent());
    }
    // Calculate sequence number stats per card
    auto& seq_nr_for_card=m_seq_nr_per_card.at(wlan_idx);
    seq_nr_for_card->on_new_sequence_number((uint16_t)nonce);
    m_rx_stats_per_card.at(wlan_idx).curr_packet_loss=seq_nr_for_card->get_current_loss_percent();
    return true;
  }
  //m_console->debug("Got non-wb packet {}",radio_port);
  return false;
}

void WBTxRx::on_valid_packet(uint64_t nonce,int wlan_index,const uint8_t radioPort,const uint8_t *data, const std::size_t data_len) {
  if(m_output_cb!= nullptr){
    m_output_cb(nonce,wlan_index,radioPort,data,data_len);
  }
  // find a consumer for data of this radio port
  auto handler=m_rx_handlers.find(radioPort);
  if(handler!=m_rx_handlers.end()){
    StreamRxHandler& rxHandler=*handler->second;
    rxHandler.cb_packet(nonce,wlan_index,data,data_len);
  }
}

void WBTxRx::start_receiving() {
  keep_receiving= true;
  m_receive_thread=std::make_unique<std::thread>([this](){
    loop_receive_packets();
  });
}

void WBTxRx::stop_receiving() {
  keep_receiving= false;
  if(m_receive_thread!= nullptr){
    if(m_receive_thread->joinable()){
      m_receive_thread->join();
    }
    m_receive_thread= nullptr;
  }
}

void WBTxRx::announce_session_key_if_needed() {
  const auto cur_ts = std::chrono::steady_clock::now();
  if (cur_ts >= m_session_key_announce_ts) {
    // Announce session key
    send_session_key();
    m_session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
  }
}

void WBTxRx::send_session_key() {
  RadiotapHeader tmp_radiotap_header=m_radiotap_header;
  Ieee80211Header tmp_ieee_hdr=mIeee80211Header;
  tmp_ieee_hdr.writeParams(RADIO_PORT_SESSION_KEY_PACKETS,0);
  auto packet=wifibroadcast::pcap_helper::create_radiotap_wifi_packet(tmp_radiotap_header,tmp_ieee_hdr,
                                                          (uint8_t *)&m_tx_sess_key_packet, sizeof(SessionKeyPacket));
  // NOTE: Session key is always sent via card 0 since otherwise we might pick up the session key intended for the ground unit
  // from the air unit !
  pcap_t *tx= m_pcap_handles[0].rx;
  const auto len_injected=pcap_inject(tx,packet.data(),packet.size());
  if (len_injected != (int) packet.size()) {
    // This basically should never fail - if the tx queue is full, pcap seems to wait ?!
    m_console->warn("pcap -unable to inject packet size:{} ret:{} err:[{}]",packet.size(),len_injected, pcap_geterr(tx));
  }
}

void WBTxRx::tx_update_mcs_index(uint8_t mcs_index) {
  m_console->debug("update_mcs_index {}",mcs_index);
  m_radioTapHeaderParams.mcs_index=mcs_index;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTxRx::tx_update_channel_width(int width_mhz) {
  m_console->debug("update_channel_width {}",width_mhz);
  m_radioTapHeaderParams.bandwidth=width_mhz;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTxRx::tx_update_stbc(int stbc) {
  m_console->debug("update_stbc {}",stbc);
  if(stbc<0 || stbc> 3){
    m_console->warn("Invalid stbc index");
    return ;
  }
  m_radioTapHeaderParams.stbc=stbc;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTxRx::tx_update_guard_interval(bool short_gi) {
  m_radioTapHeaderParams.short_gi=short_gi;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTxRx::tx_update_ldpc(bool ldpc) {
  m_radioTapHeaderParams.ldpc=ldpc;
  tx_threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTxRx::tx_threadsafe_update_radiotap_header(const RadiotapHeader::UserSelectableParams &params) {
  auto newRadioTapHeader=RadiotapHeader{params};
  std::lock_guard<std::mutex> guard(m_tx_mutex);
  m_radiotap_header = newRadioTapHeader;
}

WBTxRx::TxStats WBTxRx::get_tx_stats() {
    return m_tx_stats;
}

WBTxRx::RxStats WBTxRx::get_rx_stats() {
  WBTxRx::RxStats ret=m_rx_stats;
  ret.curr_packet_loss=m_seq_nr_helper.get_current_loss_percent();
  return ret;
}

WBTxRx::RxStatsPerCard WBTxRx::get_rx_stats_for_card(int card_index) {
  return m_rx_stats_per_card.at(card_index);
}

void WBTxRx::rx_reset_stats() {
  m_rx_stats=RxStats{};
}

bool WBTxRx::is_card_active_tx(int card_idx) {
  if(card_idx==m_curr_tx_card)return true;
  return false;
}
