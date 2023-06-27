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
  assert(!m_wifi_cards.empty());
  for(const auto& card: m_wifi_cards){
    m_pcap_handles.push_back(PcapTxRx{});
  }
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
  memcpy(packet_buff+RadiotapHeader::SIZE_BYTES,mIeee80211Header.getData(),Ieee80211Header::SIZE_BYTES);
  // encrypt and copy over the packet
  uint8_t* encrypted_data_dest=packet_buff+RadiotapHeader::SIZE_BYTES+Ieee80211Header::SIZE_BYTES+sizeof(uint64_t);
  const auto ciphertext_len=m_encryptor->encrypt2(m_nonce,data,data_len,encrypted_data_dest);
  /*long long unsigned int ciphertext_len;
  crypto_aead_chacha20poly1305_encrypt(encrypted_data_dest, &ciphertext_len,
                                       data, data_len,
                                       (uint8_t *)nullptr, 0,
                                       nullptr,
                                       (uint8_t *) m_nonce, session_key.data());*/

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
      continue;
    }
    // TODO Optimization: If rc>1 we have data on more than one wifi card. It would be better to alternating process a couple of packets from card 1, then card 2 or similar
    for (int i = 0; rc > 0 && i < mReceiverFDs.size(); i++) {
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

  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt, true);
  const uint8_t *pkt_payload = parsedPacket->payload;
  const size_t pkt_payload_size = parsedPacket->payloadSize;

  auto radio_port=0;

  if(radio_port==0){
    // (might) be an openhd session key packet

  }

  process_received_data_packet(0,pkt,hdr.len);
}


void TxRxInstance::process_received_data_packet(uint8_t wlan_idx,
                                                const uint8_t *pkt_payload,
                                                const size_t pkt_payload_size) {
  std::shared_ptr<std::vector<uint8_t>> decrypted=std::make_shared<std::vector<uint8_t>>(pkt_payload_size-sizeof(uint64_t)-crypto_aead_chacha20poly1305_ABYTES);
  // nonce comes first
  auto* nonce=(uint64_t*) pkt_payload;
  // after that, we have the encrypted data (and the encryption suffix)
  const uint8_t* encrypted_data_with_suffix=pkt_payload+sizeof(uint64_t);
  const auto encrypted_data_with_suffix_len = pkt_payload_size-sizeof(uint64_t);
  const auto res=m_decryptor->decrypt2(*nonce,encrypted_data_with_suffix,encrypted_data_with_suffix_len,
                                         decrypted->data(),decrypted->size());
  if(res!=-1){
    on_valid_packet(0,0,decrypted);
  }
}

void TxRxInstance::on_valid_packet(int wlan_index, uint8_t radio_port,std::shared_ptr<std::vector<uint8_t>> data) {

}
