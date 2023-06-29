//
// Created by consti10 on 28.06.23.
//

#ifndef WIFIBROADCAST_FECENABLED2_H
#define WIFIBROADCAST_FECENABLED2_H

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "FEC.hpp"
#include "HelperSources/TimeHelper.hpp"
#include "WBReceiverStats.hpp"
#include "wifibroadcast-spdlog.h"

static_assert(__BYTE_ORDER == __LITTLE_ENDIAN, "This code is written for little endian only !");

namespace bla{

struct FECPayloadHdr{
  // Most often each frame is encoded as one fec block
  // rolling
  uint16_t block_idx;
  // each fragment inside a block has a fragment index
  uint16_t fragment_idx;
  // how many fragments make up the primary fragments part, the rest is secondary fragments
  // note that we do not need to know how many secondary fragments have been created - as soon as we
  // 'have enough', we can perform the FEC correction step if necessary
  uint16_t n_primary_fragments;
  // For FEC all data fragments have to be the same size. We pad the rest during encoding / decoding with 0,
  // and do this when encoding / decoding such that the 0 bytes don't have to be transmitted.
  // This needs to be included during the fec encode / decode step !
  uint16_t data_size;
}__attribute__ ((packed));
static_assert(sizeof(FECPayloadHdr)==8);

// 1510-(13+24+9+16+2)
//A: Any UDP with packet size <= 1466. For example x264 inside RTP or Mavlink.
// set here to remove dependency on wifibroadcast.hpp
static constexpr const auto FEC_MAX_PACKET_SIZE = 1448-2;
//static constexpr const auto FEC_MAX_PACKET_SIZE= WB_FRAME_MAX_PAYLOAD;
static constexpr const auto FEC_MAX_PAYLOAD_SIZE = FEC_MAX_PACKET_SIZE - sizeof(FECPayloadHdr);
static_assert(FEC_MAX_PAYLOAD_SIZE == 1446-8);

// max 255 primary and secondary fragments together for now. Theoretically, this implementation has enough bytes in the header for
// up to 15 bit fragment indices, 2^15=32768
// Note: currently limited by the fec c implementation
static constexpr const uint16_t MAX_N_P_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t MAX_N_S_FRAGMENTS_PER_BLOCK = 128;
static constexpr const uint16_t
    MAX_TOTAL_FRAGMENTS_PER_BLOCK = MAX_N_P_FRAGMENTS_PER_BLOCK + MAX_N_S_FRAGMENTS_PER_BLOCK;

// For dynamic block sizes, we switched to a FEC overhead "percentage" value.
// e.g. the final data throughput ~= original data throughput * fec overhead percentage
static uint32_t calculate_n_secondary_fragments(uint32_t n_primary_fragments,uint32_t fec_overhead_perc){
  if(fec_overhead_perc<=0)return 0;
  return std::lroundf(static_cast<float>(n_primary_fragments) * static_cast<float>(fec_overhead_perc) / 100.0f);
}
// calculate n from k and percentage as used in FEC terms
// (k: number of primary fragments, n: primary + secondary fragments)
static unsigned int calculateN(const unsigned int k, const unsigned int percentage) {
  return k + calculate_n_secondary_fragments(k,percentage);
}

class FECEncoder {
 public:
  typedef std::function<void(const uint8_t* packet,int packet_len)>
      OUTPUT_DATA_CALLBACK;
  OUTPUT_DATA_CALLBACK outputDataCallback;
  explicit FECEncoder()=default;
  FECEncoder(const FECEncoder &other) = delete;
  // Pre-allocated to have space for storing primary fragments (they are needed once the fec step needs to be performed)
  // and creating the wanted amount of secondary packets
  std::array<std::array<uint8_t, FEC_MAX_PACKET_SIZE>,MAX_TOTAL_FRAGMENTS_PER_BLOCK> m_block_buffer{};
  uint16_t m_curr_block_idx=0;
  AvgCalculator m_fec_block_encode_time;
  MinMaxAvg<std::chrono::nanoseconds> m_curr_fec_block_encode_time{};
  BaseAvgCalculator<uint16_t> m_block_sizes{};
  MinMaxAvg<uint16_t> m_curr_fec_block_sizes{};
 public:
  void encode_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> data_packets,int n_secondary_fragments){
    const auto n_primary_fragments=data_packets.size();
    // nice to have statistic
    m_block_sizes.add(n_primary_fragments);
    if(m_block_sizes.get_delta_since_last_reset()>=std::chrono::seconds(1)){
      //wifibroadcast::log::get_default()->debug("Block sizes: {}",m_block_sizes.getAvgReadable());
      m_curr_fec_block_sizes=m_block_sizes.getMinMaxAvg();
      m_block_sizes.reset();
    }
    FECPayloadHdr header{};
    header.block_idx=m_curr_block_idx;
    m_curr_block_idx++;
    header.n_primary_fragments=n_primary_fragments;
    // write and forward all the data packets first
    // also calculate the size of the biggest data packet
    size_t max_packet_size=0;
    // Store a pointer where the FEC data begins for performing the FEC step later on
    std::vector<const uint8_t *> primary_fragments_data_p;
    for(int i=0;i<data_packets.size();i++){
      const auto& data_fragment=data_packets[i];
      //wifibroadcast::log::get_default()->debug("In:{}",(int)data_fragment->size());
      assert(data_fragment->size()>0);
      assert(data_fragment->size()<=FEC_MAX_PAYLOAD_SIZE);
      header.fragment_idx=i;
      header.data_size=data_fragment->size();
      auto buffer_p=m_block_buffer[i].data();
      // copy over the header
      memcpy(buffer_p,(uint8_t*)&header,sizeof(FECPayloadHdr));
      // write the actual data
      memcpy(buffer_p + sizeof(FECPayloadHdr), data_fragment->data(),data_fragment->size());
      // zero out the remaining bytes such that FEC always sees zeroes
      // same is done on the rx. These zero bytes are never transmitted via wifi
      const auto writtenDataSize = sizeof(FECPayloadHdr) + data_fragment->size();
      memset(buffer_p + writtenDataSize, 0, FEC_MAX_PACKET_SIZE - writtenDataSize);
      max_packet_size = std::max(max_packet_size, data_fragment->size());
      // we can forward the data packet immediately via the callback
      if(outputDataCallback){
        outputDataCallback(buffer_p,writtenDataSize);
      }
      // NOTE: FECPayloadHdr::data_size needs to be included during the fec encode step
      primary_fragments_data_p.push_back(buffer_p+sizeof(FECPayloadHdr)-sizeof(uint16_t));
    }
    // then we create as many FEC packets as needed
    if(n_secondary_fragments==0){
      //wifibroadcast::log::get_default()->debug("No FEC step performed");
      // no FEC step is actually performed, usefully for debugging / performance evaluation
      return ;
    }
    const auto before=std::chrono::steady_clock::now();
    // Now we perform the actual FEC encode step
    std::vector<uint8_t*> secondary_fragments_data_p;
    for(int i=0;i<n_secondary_fragments;i++){
      auto fragment_index=i+n_primary_fragments;
      auto buffer_p=m_block_buffer[fragment_index].data();
      header.fragment_idx=fragment_index;
      // copy over the header
      memcpy(buffer_p,(uint8_t*)&header,sizeof(FECPayloadHdr));
      // where the FEC packet correction data is written to
      secondary_fragments_data_p.push_back(buffer_p+sizeof(FECPayloadHdr)-sizeof(uint16_t));
    }
    fec_encode2(max_packet_size+sizeof(uint16_t),primary_fragments_data_p,secondary_fragments_data_p);
    m_fec_block_encode_time.add(std::chrono::steady_clock::now()-before);
    if(m_fec_block_encode_time.get_delta_since_last_reset()>=std::chrono::seconds(1)){
      //wifibroadcast::log::get_default()->debug("FEC encode time:{}",m_fec_block_encode_time.getAvgReadable());
      m_curr_fec_block_encode_time=m_fec_block_encode_time.getMinMaxAvg();
      m_fec_block_encode_time.reset();
    }
    // and forward all the FEC correction packets
    for(int i=0;i<n_secondary_fragments;i++){
      auto fragment_index=i+n_primary_fragments;
      if(outputDataCallback){
        outputDataCallback(m_block_buffer[fragment_index].data(),sizeof(FECPayloadHdr)+max_packet_size);
      }
    }
  }
};

// This encapsulates everything you need when working on a single FEC block on the receiver
// for example, addFragment() or pullAvailablePrimaryFragments()
// it also provides convenient methods to query if the block is fully forwarded
// or if it is ready for the FEC reconstruction step.
class RxBlock {
 public:
  // @param maxNFragmentsPerBlock max number of primary and secondary fragments for this block.
  // you could just use MAX_TOTAL_FRAGMENTS_PER_BLOCK for that, but if your tx then uses (4:8) for example, you'd
  // allocate much more memory every time for a new RX block than needed.
  explicit RxBlock(const unsigned int maxNFragmentsPerBlock, const uint64_t blockIdx1)
      :blockIdx(blockIdx1),
        fragment_map(maxNFragmentsPerBlock,FragmentStatus::UNAVAILABLE), //after creation of the RxBlock every f. is marked as unavailable
        blockBuffer(maxNFragmentsPerBlock) {
    assert(fragment_map.size() == blockBuffer.size());
  }
  // No copy constructor for safety
  RxBlock(const RxBlock &) = delete;
  // two blocks are the same if they refer to the same block idx:
  constexpr bool operator==(const RxBlock &other) const {
    return blockIdx == other.blockIdx;
  }
  // same for not equal operator
  constexpr bool operator!=(const RxBlock &other) const {
    return !(*this == other);
  }
  ~RxBlock() = default;
 public:
  // returns true if this fragment has been already received
  bool hasFragment(const FECPayloadHdr &header) {
    assert(header.block_idx == blockIdx);
    return fragment_map[header.fragment_idx] == AVAILABLE;
  }
  // returns true if we are "done with this block" aka all data has been already forwarded
  bool allPrimaryFragmentsHaveBeenForwarded() const {
    if (m_n_primary_fragments_in_block == -1)return false;
    return nAlreadyForwardedPrimaryFragments == m_n_primary_fragments_in_block;
  }
  // returns true if enough FEC secondary fragments are available to replace all missing primary fragments
  bool allPrimaryFragmentsCanBeRecovered() const {
    // return false if k is not known for this block yet (which means we didn't get a secondary fragment yet,
    // since each secondary fragment contains k)
    if (m_n_primary_fragments_in_block == -1)return false;
    // ready for FEC step if we have as many secondary fragments as we are missing on primary fragments
    if (m_n_available_primary_fragments + m_n_available_secondary_fragments >=
        m_n_primary_fragments_in_block)return true;
    return false;
  }
  // returns true if suddenly all primary fragments have become available
  bool allPrimaryFragmentsAreAvailable() const {
    if (m_n_primary_fragments_in_block == -1)return false;
    return m_n_available_primary_fragments == m_n_primary_fragments_in_block;
  }
  // copy the fragment data and mark it as available
  // you should check if it is already available with hasFragment() to avoid storing a fragment multiple times
  // when using multiple RX cards
  void addFragment(const uint8_t *data, const std::size_t dataLen) {
    auto* hdr_p=(FECPayloadHdr*) data;
    FECPayloadHdr& header=*hdr_p;
    assert(!hasFragment(header));
    assert(header.block_idx == blockIdx);
    assert(fragment_map[header.fragment_idx] == UNAVAILABLE);
    assert(header.fragment_idx < blockBuffer.size());
    fragment_copy_payload(header.fragment_idx,data,dataLen);
    // mark it as available
    fragment_map[header.fragment_idx] = FragmentStatus::AVAILABLE;

    // each fragment inside a block should report the same n of primary fragments
    if(m_n_primary_fragments_in_block ==-1){
      m_n_primary_fragments_in_block =header.n_primary_fragments;
    }else{
      assert(m_n_primary_fragments_in_block ==header.n_primary_fragments);
    }
    const bool is_primary_fragment=header.fragment_idx<header.n_primary_fragments;
    if(is_primary_fragment){
      m_n_available_primary_fragments++;
    }else{
      m_n_available_secondary_fragments++;
      const auto payload_len_including_size=dataLen-sizeof(FECPayloadHdr)+sizeof(uint16_t);
      // all secondary fragments shall have the same size
      if(m_size_of_secondary_fragments ==-1){
        m_size_of_secondary_fragments =payload_len_including_size;
      }else{
        assert(m_size_of_secondary_fragments ==payload_len_including_size);
      }
    }
    if(firstFragmentTimePoint==std::nullopt){
      firstFragmentTimePoint=std::chrono::steady_clock::now();
    }
  }
  void fragment_copy_payload(const int fragment_idx,const uint8_t *data, const std::size_t dataLen){
    uint8_t* buff=blockBuffer[fragment_idx].data();
    // NOTE: FECPayloadHdr::data_size needs to be included during the fec decode step
    const uint8_t* payload_p=data+sizeof(FECPayloadHdr)-sizeof(uint16_t);
    auto payload_s=dataLen-sizeof(FECPayloadHdr)+sizeof(uint16_t);
    // write the data (doesn't matter if FEC data or correction packet)
    memcpy(buff, payload_p,payload_s);
    // set the rest to zero such that FEC works
    memset(buff+payload_s, 0, FEC_MAX_PACKET_SIZE - payload_s);
  }
  /**
   * @returns the indices for all primary fragments that have not yet been forwarded and are available (already received or reconstructed).
   * Once an index is returned here, it won't be returned again
   * (Therefore, as long as you immediately forward all primary fragments returned here,everything happens in order)
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block */
  std::vector<uint16_t> pullAvailablePrimaryFragments(const bool discardMissingPackets = false) {
    // note: when pulling the available fragments, we do not need to know how many primary fragments this block actually contains
    std::vector<uint16_t> ret;
    for (int i = nAlreadyForwardedPrimaryFragments; i < m_n_available_primary_fragments; i++) {
      if (fragment_map[i] == FragmentStatus::UNAVAILABLE) {
        if (discardMissingPackets) {
          continue;
        } else {
          break;
        }
      }
      ret.push_back(i);
    }
    // make sure these indices won't be returned again
    nAlreadyForwardedPrimaryFragments += (int) ret.size();
    return ret;
  }
  const uint8_t *get_primary_fragment_data_p(const int fragment_index){
    assert(fragment_map[fragment_index] == AVAILABLE);
    assert(m_n_primary_fragments_in_block !=-1);
    assert(fragment_index< m_n_primary_fragments_in_block);
    //return blockBuffer[fragment_index].data()+sizeof(FECPayloadHdr);
    return blockBuffer[fragment_index].data()+sizeof(uint16_t);
  }
  const int get_primary_fragment_data_size(const int fragment_index){
    assert(fragment_map[fragment_index] == AVAILABLE);
    assert(m_n_primary_fragments_in_block !=-1);
    assert(fragment_index< m_n_primary_fragments_in_block);
    uint16_t* len_p=(uint16_t*)blockBuffer[fragment_index].data();
    return *len_p;
  }

  // returns the n of primary and secondary fragments for this block
  int getNAvailableFragments() const {
    return m_n_available_primary_fragments + m_n_available_secondary_fragments;
  }
  // make sure to check if enough secondary fragments are available before calling this method !
  // reconstructing only part of the missing data is not supported !
  // return: the n of reconstructed packets
  int reconstructAllMissingData() {
    //wifibroadcast::log::get_default()->debug("reconstructAllMissingData"<<nAvailablePrimaryFragments<<" "<<nAvailableSecondaryFragments<<" "<<fec.FEC_K<<"\n";
    // NOTE: FEC does only work if nPrimaryFragments+nSecondaryFragments>=FEC_K
    assert(m_n_primary_fragments_in_block != -1);
    assert(m_size_of_secondary_fragments != -1);
    // do not reconstruct if reconstruction is impossible
    assert(getNAvailableFragments() >= m_n_primary_fragments_in_block);
    // also do not reconstruct if reconstruction is not needed
   // const int nMissingPrimaryFragments = m_n_primary_fragments_in_block- m_n_available_primary_fragments;
    auto recoveredFragmentIndices = fecDecode(m_size_of_secondary_fragments, blockBuffer,
                  m_n_primary_fragments_in_block, fragment_map);
    for (const auto idx: recoveredFragmentIndices) {
      fragment_map[idx] = AVAILABLE;
    }
    m_n_available_primary_fragments += recoveredFragmentIndices.size();
    // n of reconstructed packets
    return recoveredFragmentIndices.size();
  }
  [[nodiscard]] uint64_t getBlockIdx() const {
    return blockIdx;
  }
  [[nodiscard]] std::optional<std::chrono::steady_clock::time_point> getFirstFragmentTimePoint() const {
    return firstFragmentTimePoint;
  }
  // Returns the number of missing primary packets (e.g. the n of actual data packets that are missing)
  // This only works if we know the "fec_k" parameter
  /*std::optional<int> get_missing_primary_packets(){
    if(fec_k<=0)return std::nullopt;
    return fec_k-nAvailablePrimaryFragments;
  }*/
  std::string get_missing_primary_packets_readable(){
    /*const auto tmp=get_missing_primary_packets();
    if(tmp==std::nullopt)return "?";
    return std::to_string(tmp.value());*/
    return "TODO";
  }
 private:
  // the block idx marks which block this element refers to
  const uint64_t blockIdx = 0;
  // n of primary fragments that are already pulled out
  int nAlreadyForwardedPrimaryFragments = 0;
  // for each fragment (via fragment_idx) store if it has been received yet
  std::vector<FragmentStatus> fragment_map;
  // holds all the data for all received fragments (if fragment_map says UNAVALIABLE at this position, content is undefined)
  std::vector<std::array<uint8_t, FEC_MAX_PACKET_SIZE>> blockBuffer;
  // time point when the first fragment for this block was received (via addFragment() )
  std::optional<std::chrono::steady_clock::time_point> firstFragmentTimePoint = std::nullopt;
  // as soon as we know any of the fragments for this block, we know how many primary fragments this block contains
  // (and therefore, how many primary or secondary fragments we need to fully reconstruct)
  int m_n_primary_fragments_in_block =-1;
  // for the fec step, we need the size of the fec secondary fragments, which should be equal for all secondary fragments
  int m_size_of_secondary_fragments =-1;
  int m_n_available_primary_fragments =0;
  int m_n_available_secondary_fragments =0;
};

// Takes a continuous stream of packets (data and fec correction packets) and
// processes them such that the output is exactly (or as close as possible) to the
// Input stream fed to FECEncoder.
// Most importantly, it also handles re-ordering of packets and packet duplicates due to multiple rx cards
class FECDecoder {
 public:
  // Does not need to know k,n or if tx does variable block length or not.
  // If the tx doesn't use the full range of fragment indices (aka K is fixed) use
  // @param maxNFragmentsPerBlock for a more efficient memory usage
  explicit FECDecoder(const unsigned int rx_queue_max_depth,const unsigned int maxNFragmentsPerBlock = MAX_TOTAL_FRAGMENTS_PER_BLOCK,
                      bool enable_log_debug=false) :
                                                       RX_QUEUE_MAX_SIZE(rx_queue_max_depth),
                                                       maxNFragmentsPerBlock(maxNFragmentsPerBlock),
                                                       m_enable_log_debug(enable_log_debug){
    assert(rx_queue_max_depth<20);
    assert(rx_queue_max_depth>=1);
  }
  FECDecoder(const FECDecoder &other) = delete;
  ~FECDecoder() = default;
  // data forwarded on this callback is always in-order but possibly with gaps
  typedef std::function<void(const uint8_t *payload, std::size_t payloadSize)> SEND_DECODED_PACKET;
  // WARNING: Don't forget to register this callback !
  SEND_DECODED_PACKET mSendDecodedPayloadCallback;
  // A value too high doesn't really give much benefit and increases memory usage
  const unsigned int RX_QUEUE_MAX_SIZE;
  const unsigned int maxNFragmentsPerBlock;
  const bool m_enable_log_debug;
  AvgCalculator m_fec_decode_time{};
 public:
  bool validate_and_process_packet(const uint8_t* data,int data_len){
    if(data_len<sizeof(FECPayloadHdr)){
      wifibroadcast::log::get_default()->warn("too small packet size:{}",data_len);
    }
    // reconstruct the data layout
    const FECPayloadHdr* header_p=(FECPayloadHdr*)data;
   /* const uint8_t* payload_p=data+sizeof(FECPayloadHdr);
    const int payload_size=data_len-sizeof(FECPayloadHdr);*/
    if (header_p->fragment_idx >= maxNFragmentsPerBlock) {
      wifibroadcast::log::get_default()->warn("invalid fragment_idx: {}",header_p->fragment_idx);
      return false;
    }
    process_with_rx_queue(*header_p,data,data_len);
    return true;
  }
 private:
  // since we also need to search this data structure, a std::queue is not enough.
  // since we have an upper limit on the size of this dequeue, it is basically a searchable ring buffer
  std::deque<std::unique_ptr<RxBlock>> rx_queue;
  uint64_t last_known_block = ((uint64_t) -1);  //id of last known block
  /**
   * For this Block,
   * starting at the primary fragment we stopped on last time,
   * forward as many primary fragments as they are available until there is a gap
   * @param discardMissingPackets : if true, gaps are ignored and fragments are forwarded even though this means the missing ones are irreversible lost
   * Be carefully with this param, use it only before you need to get rid of a block
   */
  void forwardMissingPrimaryFragmentsIfAvailable(RxBlock &block, const bool discardMissingPackets = false){
    assert(mSendDecodedPayloadCallback);
    // TODO remove me
    if(discardMissingPackets){
      if(m_enable_log_debug){
        wifibroadcast::log::get_default()->warn("Forwarding block that is not yet fully finished: {} with n fragments: {} missing: {}",
                                                block.getBlockIdx(),block.getNAvailableFragments(),block.get_missing_primary_packets_readable());
      }
    }
    const auto indices = block.pullAvailablePrimaryFragments(discardMissingPackets);
    for (auto primaryFragmentIndex: indices) {
      const uint8_t* data=block.get_primary_fragment_data_p(primaryFragmentIndex);
      const int data_size=block.get_primary_fragment_data_size(primaryFragmentIndex);
      if (data_size > FEC_MAX_PAYLOAD_SIZE || data_size <= 0) {
        wifibroadcast::log::get_default()->warn("corrupted packet on FECDecoder out ({}:{}) : {}B",block.getBlockIdx(),primaryFragmentIndex,data_size);
      } else {
        mSendDecodedPayloadCallback(data, data_size);
        stats.count_bytes_forwarded+=data_size;
      }
    }
  }
  // also increase lost block count if block is not fully recovered
  void rxQueuePopFront() {
    assert(rx_queue.front() != nullptr);
    if (!rx_queue.front()->allPrimaryFragmentsHaveBeenForwarded()) {
      stats.count_blocks_lost++;
    }
    rx_queue.pop_front();
  }
  // create a new RxBlock for the specified block_idx and push it into the queue
  // NOTE: Checks first if this operation would increase the size of the queue over its max capacity
  // In this case, the only solution is to remove the oldest block before adding the new one
  void rxRingCreateNewSafe(const uint64_t blockIdx) {
    // check: make sure to always put blocks into the queue in order !
    if (!rx_queue.empty()) {
      // the newest block in the queue should be equal to block_idx -1
      // but it must not ?!
      if (rx_queue.back()->getBlockIdx() != (blockIdx - 1)) {
        // If we land here, one or more full blocks are missing, which can happen on bad rx links
        //wifibroadcast::log::get_default()->debug("In queue: {} But new: {}",rx_queue.back()->getBlockIdx(),blockIdx);
      }
      //assert(rx_queue.back()->getBlockIdx() == (blockIdx - 1));
    }
    // we can return early if this operation doesn't exceed the size limit
    if (rx_queue.size() < RX_QUEUE_MAX_SIZE) {
      rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock, blockIdx));
      stats.count_blocks_total++;
      return;
    }
    //Ring overflow. This means that there are more unfinished blocks than ring size
    //Possible solutions:
    //1. Increase ring size. Do this if you have large variance of packet travel time throught WiFi card or network stack.
    //   Some cards can do this due to packet reordering inside, diffent chipset and/or firmware or your RX hosts have different CPU power.
    //2. Reduce packet injection speed or try to unify RX hardware.

    // forward remaining data for the (oldest) block, since we need to get rid of it
    auto &oldestBlock = rx_queue.front();
    forwardMissingPrimaryFragmentsIfAvailable(*oldestBlock, true);
    // and remove the block once done with it
    rxQueuePopFront();

    // now we are guaranteed to have space for one new block
    rx_queue.push_back(std::make_unique<RxBlock>(maxNFragmentsPerBlock, blockIdx));
    stats.count_blocks_total++;
  }

  // If block is already known and not in the queue anymore return nullptr
  // else if block is inside the ring return pointer to it
  // and if it is not inside the ring add as many blocks as needed, then return pointer to it
  RxBlock *rxRingFindCreateBlockByIdx(const uint64_t blockIdx) {
    // check if block is already in the ring
    auto found = std::find_if(rx_queue.begin(), rx_queue.end(),
                              [&blockIdx](const std::unique_ptr<RxBlock> &block) {
                                return block->getBlockIdx() == blockIdx;
                              });
    if (found != rx_queue.end()) {
      return found->get();
    }
    // check if block is already known and not in the ring then it is already processed
    if (last_known_block != (uint64_t) -1 && blockIdx <= last_known_block) {
      return nullptr;
    }

    // don't forget to increase the lost blocks counter if we do not add blocks here due to no space in the rx queue
    // (can happen easily if the rx queue has a size of 1)
    const auto n_needed_new_blocks = last_known_block != (uint64_t) -1 ? blockIdx - last_known_block : 1;
    if(n_needed_new_blocks>RX_QUEUE_MAX_SIZE){
      stats.count_blocks_lost+=n_needed_new_blocks-RX_QUEUE_MAX_SIZE;
    }
    // add as many blocks as we need ( the rx ring mustn't have any gaps between the block indices).
    // but there is no point in adding more blocks than RX_RING_SIZE
    const int new_blocks = (int) std::min(n_needed_new_blocks,
                                         (uint64_t) FECDecoder::RX_QUEUE_MAX_SIZE);
    last_known_block = blockIdx;

    for (int i = 0; i < new_blocks; i++) {
      rxRingCreateNewSafe(blockIdx + i + 1 - new_blocks);
    }
    // the new block we've added is now the most recently added element (and since we always push to the back, the "back()" element)
    assert(rx_queue.back()->getBlockIdx() == blockIdx);
    return rx_queue.back().get();
  }
  void process_with_rx_queue(const FECPayloadHdr& header,const uint8_t* data,int data_size){
    auto blockP = rxRingFindCreateBlockByIdx(header.block_idx);
    //ignore already processed blocks
    if (blockP == nullptr) return;
    // cannot be nullptr
    RxBlock &block = *blockP;
    // ignore already processed fragments
    if (block.hasFragment(header)) {
      return;
    }
    block.addFragment(data,data_size);
    if (block == *rx_queue.front()) {
      //wifibroadcast::log::get_default()->debug("In front\n";
      // we are in the front of the queue (e.g. at the oldest block)
      // forward packets until the first gap
      forwardMissingPrimaryFragmentsIfAvailable(block);
      // We are done with this block if either all fragments have been forwarded or it can be recovered
      if (block.allPrimaryFragmentsHaveBeenForwarded()) {
        // remove block when done with it
        rxQueuePopFront();
        return;
      }
      if (block.allPrimaryFragmentsCanBeRecovered()) {
        // apply fec for this block
        const auto before_encode=std::chrono::steady_clock::now();
        stats.count_fragments_recovered += block.reconstructAllMissingData();
        stats.count_blocks_recovered++;
        m_fec_decode_time.add(std::chrono::steady_clock::now()-before_encode);
        if(m_fec_decode_time.get_delta_since_last_reset()>std::chrono::seconds(1)){
          //wifibroadcast::log::get_default()->debug("FEC decode took {}",m_fec_decode_time.getAvgReadable());
          stats.curr_fec_decode_time=m_fec_decode_time.getMinMaxAvg();
          m_fec_decode_time.reset();
        }
        forwardMissingPrimaryFragmentsIfAvailable(block);
        assert(block.allPrimaryFragmentsHaveBeenForwarded());
        // remove block when done with it
        rxQueuePopFront();
        return;
      }
      return;
    } else {
      //wifibroadcast::log::get_default()->debug("Not in front\n";
      // we are not in the front of the queue but somewhere else
      // If this block can be fully recovered or all primary fragments are available this triggers a flush
      if (block.allPrimaryFragmentsAreAvailable() || block.allPrimaryFragmentsCanBeRecovered()) {
        // send all queued packets in all unfinished blocks before and remove them
        while (block != *rx_queue.front()) {
          forwardMissingPrimaryFragmentsIfAvailable(*rx_queue.front(), true);
          rxQueuePopFront();
        }
        // then process the block who is fully recoverable or has no gaps in the primary fragments
        if (block.allPrimaryFragmentsAreAvailable()) {
          forwardMissingPrimaryFragmentsIfAvailable(block);
          assert(block.allPrimaryFragmentsHaveBeenForwarded());
        } else {
          // apply fec for this block
          stats.count_fragments_recovered += block.reconstructAllMissingData();
          stats.count_blocks_recovered++;
          forwardMissingPrimaryFragmentsIfAvailable(block);
          assert(block.allPrimaryFragmentsHaveBeenForwarded());
        }
        // remove block
        rxQueuePopFront();
      }
    }
  }
 public:
  FECRxStats stats{};
};

// quick math regarding sequence numbers:
//uint32_t holds max 4294967295 . At 10 000 pps (packets per seconds) (which is already completely out of reach) this allows the tx to run for 429496.7295 seconds
// 429496.7295 / 60 / 60 = 119.304647083 hours which is also completely overkill for OpenHD (and after this time span, a "reset" of the sequence number happens anyways)
// unsigned 24 bits holds 16777215 . At 1000 blocks per second this allows the tx to create blocks for 16777.215 seconds or 4.6 hours. That should cover a flight (and after 4.6h a reset happens,
// which means you might lose a couple of blocks once every 4.6 h )
// and 8 bits holds max 255.

}

#endif  // WIFIBROADCAST_FECENABLED2_H
