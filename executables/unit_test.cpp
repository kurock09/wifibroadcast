
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

#include <cassert>
#include <chrono>
#include <cinttypes>
#include <climits>
#include <cstdio>
#include <ctime>
#include <memory>
#include <sstream>
#include <string>

#include "../src/FECEnabled.h"
//#include "../src/FECEnabled.hpp"

#include "../src/HelperSources/Helper.hpp"
#include "../src/Encryption.hpp"
#include "../src/wifibroadcast-spdlog.h"

// Simple unit testing for the FEC lib that doesn't require wifi cards

namespace TestFEC {

// Chooses randomly
// 1) block size (n fragments in block)
// 2) size of data in each fragment in a block
// 3) a fec overhead value (k)
// 4) a specific amount of dropped packets, but keeping enough packets to be fully recoverable
static void test_random_bs_fs_overhead_dropped(){
  wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped begin");
  std::vector<std::vector<std::vector<uint8_t>>> fragmented_frames_in;
  std::vector<std::vector<uint8_t>> fragmented_frames_sequential_in;
  for(int i=0;i<1000*2;i++){
    std::vector<std::vector<uint8_t>> fragmented_frame;
    const auto n_fragments=GenericHelper::create_random_number_between(1,MAX_N_P_FRAGMENTS_PER_BLOCK);
    for(int j=0;j<n_fragments;j++){
      const auto buff_size=GenericHelper::create_random_number_between(1,FEC_MAX_PAYLOAD_SIZE);
      //const auto buff_size=GenericHelper::create_random_number_between(12,12);
      auto buff=GenericHelper::createRandomDataBuffer(buff_size);
      fragmented_frame.push_back(buff);
      fragmented_frames_sequential_in.push_back(buff);
    }
    //wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped with {} fragments",fragmented_frame.size());
    fragmented_frames_in.push_back(fragmented_frame);
  }
  FECEncoder encoder{};
  FECDecoder decoder{10};
  std::vector<std::vector<uint8_t>> testOut;
  // The indices of packets we shall drop
  std::vector<unsigned int> curr_indices_of_packets_to_drop{};

  const auto cb1 = [&decoder,&curr_indices_of_packets_to_drop,&fragmented_frames_sequential_in](const uint8_t *payload, const std::size_t payloadSize)mutable {
    auto* hdr=(FECPayloadHdr*)payload;
    if(GenericHelper::vec_contains(curr_indices_of_packets_to_drop,hdr->fragment_idx)){
      wifibroadcast::log::get_default()->debug("Dropping packet {} in {}",(int)hdr->fragment_idx,(int)hdr->n_primary_fragments);
    }else{
      decoder.validate_and_process_packet(payload,payloadSize);
    }
    /*if(hdr->fragment_idx<hdr->n_primary_fragments){
      auto lol=std::vector<uint8_t>(payload+sizeof(FECPayloadHdr),payload+payloadSize);
      auto original=fragmented_frames_sequential_in[hdr->fragment_idx];
      GenericHelper::assertVectorsEqual(original,lol);
    }*/
  };
  int out_index=0;
  const auto cb2 = [&testOut,&fragmented_frames_sequential_in,&out_index](const uint8_t *payload, std::size_t payloadSize)mutable {
    auto buff=std::vector<uint8_t>(payload,payload+payloadSize);
    testOut.emplace_back(buff);
    //wifibroadcast::log::get_default()->debug("Out:{}",payloadSize);
    GenericHelper::assertVectorsEqual(fragmented_frames_sequential_in[out_index],buff);
    out_index++;
  };
  encoder.outputDataCallback = cb1;
  decoder.mSendDecodedPayloadCallback = cb2;
  for(int i=0;i<fragmented_frames_in.size();i++){
    auto fragmented_frame=fragmented_frames_in[i];
    const auto n_secondary_fragments=GenericHelper::create_random_number_between(0,MAX_N_S_FRAGMENTS_PER_BLOCK);
    //const auto n_secondary_fragments=0;
    // We'l drop a specific amount of fragments
    const auto n_fragments_to_drop=GenericHelper::create_random_number_between(0,n_secondary_fragments);
    //const auto n_fragments_to_drop=1;
    auto indices=GenericHelper::createIndices(fragmented_frame.size()+n_secondary_fragments);
    auto indices_packets_to_drop=GenericHelper::takeNRandomElements(indices,n_fragments_to_drop);
    wifibroadcast::log::get_default()->debug("Feeding block of {} fragments with {} secondary fragments and dropping {}",
                                             fragmented_frame.size(),n_secondary_fragments,n_fragments_to_drop);
    curr_indices_of_packets_to_drop=indices_packets_to_drop;
    encoder.encode_block(GenericHelper::convert_vec_of_vec_to_shared(fragmented_frame),n_secondary_fragments);
  }
  GenericHelper::assertVectorsOfVectorsEqual(fragmented_frames_sequential_in,testOut);
  wifibroadcast::log::get_default()->debug("test_random_bs_fs_overhead_dropped end");
}

// test without packet loss, dynamic block size aka
// randomly end the block at some time
static void testWithoutPacketLossDynamicBlockSize() {
  /*std::cout << "Test without packet loss dynamic block size\n";
  constexpr auto N_BLOCKS = 2000;
  const auto testIn = GenericHelper::createRandomDataBuffers(N_BLOCKS, FEC_MAX_PAYLOAD_SIZE, FEC_MAX_PAYLOAD_SIZE);
  std::vector<std::vector<uint8_t>> testOut;
  FECEncoder encoder(MAX_N_P_FRAGMENTS_PER_BLOCK, 50);
  FECDecoder decoder{10};
  const auto cb1 = [&decoder](const uint64_t nonce, const uint8_t *payload, const std::size_t payloadSize)mutable {
	decoder.validateAndProcessPacket(nonce, std::vector<uint8_t>(payload, payload + payloadSize));
  };
  const auto cb2 = [&testOut](const uint8_t *payload, std::size_t payloadSize)mutable {
	testOut.emplace_back(payload, payload + payloadSize);
  };
  encoder.outputDataCallback = cb1;
  decoder.mSendDecodedPayloadCallback = cb2;
  for (std::size_t i = 0; i < testIn.size(); i++) {
	//std::cout<<"Step\n";
	const bool endBlock = (rand() % 10) == 0;
	const auto &in = testIn[i];
	encoder.encodePacket(in.data(), in.size(), endBlock);
	const auto &out = testOut[i];
	assert(GenericHelper::compareVectors(in, out) == true);
  }*/
}
// Put packets in in such a order that the rx queue is tested
static void testRxQueue(const int k, const int percentage) {
  /*std::cout << "Test rx queue. K:" << k << " P:" << percentage << "\n";
  const auto n = FECEncoder::calculateN(k, percentage);
  constexpr auto QUEUE_SIZE = 10;
  const auto
	  testIn = GenericHelper::createRandomDataBuffers(QUEUE_SIZE * k, FEC_MAX_PAYLOAD_SIZE, FEC_MAX_PAYLOAD_SIZE);
  FECEncoder encoder(k, percentage);
  FECDecoder decoder{10};
  // begin test
  std::vector<std::pair<uint64_t, std::vector<uint8_t>>> fecPackets;
  const auto cb1 = [&fecPackets](const uint64_t nonce, const uint8_t *payload, const std::size_t payloadSize)mutable {
	fecPackets.emplace_back(nonce, std::vector<uint8_t>(payload, payload + payloadSize));
  };
  encoder.outputDataCallback = cb1;
  // process all input packets
  for (const auto &in: testIn) {
	encoder.encodePacket(in.data(), in.size());
  }
  // now add them to the decoder (queue):
  std::vector<std::vector<uint8_t>> testOut;
  const auto cb2 = [&testOut](const uint8_t *payload, std::size_t payloadSize)mutable {
	testOut.emplace_back(payload, payload + payloadSize);
  };
  decoder.mSendDecodedPayloadCallback = cb2;
  // add fragments (primary fragments only to not overcomplicate things)
  // but in the following order:
  // block 0, fragment 0, block 1, fragment 0, block 2, fragment 0, ... until block X, fragment n
  for (int frIdx = 0; frIdx < k; frIdx++) {
	for (int i = 0; i < QUEUE_SIZE; i++) {
	  const auto idx = i * n + frIdx;
	  std::cout << "adding" << idx << "\n";
	  const auto &packet = fecPackets.at(idx);
	  decoder.validateAndProcessPacket(packet.first, packet.second);
	}
  }
  // and then check if in and out match
  for (std::size_t i = 0; i < testIn.size(); i++) {
	//std::cout<<"Step\n";
	const auto &in = testIn[i];
	const auto &out = testOut[i];
	GenericHelper::assertVectorsEqual(in, out);
  }*/
}

}

namespace TestEncryption {
static void test(const bool useGeneratedFiles) {
  std::cout << "Using generated keypair (default seed otherwise):" << (useGeneratedFiles ? "y" : "n") << "\n";
  std::optional<std::string> encKey = useGeneratedFiles ? std::optional<std::string>("gs.key") : std::nullopt;
  std::optional<std::string> decKey = useGeneratedFiles ? std::optional<std::string>("drone.key") : std::nullopt;

  Encryptor encryptor{encKey};
  Decryptor decryptor{decKey};
  struct SessionStuff{
    std::array<uint8_t, crypto_box_NONCEBYTES> sessionKeyNonce{};  // random data
    std::array<uint8_t, crypto_aead_chacha20poly1305_KEYBYTES + crypto_box_MACBYTES> sessionKeyData{};
  };
  SessionStuff sessionKeyPacket;
  // make session key (tx)
  encryptor.makeNewSessionKey(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData);
  // and "receive" session key (rx)
  assert(
	  decryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData) == true);
  // now encrypt a couple of packets and decrypt them again afterwards
  for (uint64_t nonce = 0; nonce < 20; nonce++) {
	const auto data = GenericHelper::createRandomDataBuffer(FEC_MAX_PAYLOAD_SIZE);
        const auto encrypted=encryptor.encryptPacket(nonce,data.data(),data.size(), nullptr);
	const auto encrypted = encryptor.encryptPacket(nonce, data.data(), data.size(), wbDataHeader);
	const auto
		decrypted = decryptor.decryptPacket(nonce, encrypted.data(), encrypted.size(), wbDataHeader);
	assert(decrypted != std::nullopt);
	assert(GenericHelper::compareVectors(data, *decrypted) == true);
  }
  std::cout << "encryption test passed\n";
}
}

int main(int argc, char *argv[]) {
  std::cout << "Tests for Wifibroadcast\n";
  srand(time(NULL));
  int opt;
  int test_mode = 0;

  while ((opt = getopt(argc, argv, "m:")) != -1) {
	switch (opt) {
	  case 'm':test_mode = atoi(optarg);
		break;
	  default: /* '?' */
	  show_usage:
		std::cout
			<< "Usage: Unit tests for FEC and encryption. -m 0,1,2 test mode: 0==ALL, 1==FEC only 2==Encryption only\n";
		return 1;
	}
  }
  print_optimization_method();
  TestFEC::test_random_bs_fs_overhead_dropped();

  try {
	if (test_mode == 0 || test_mode == 1) {
	  std::cout << "Testing FEC\n";
	  test_gf();
	  test_fec();
	  testFecCPlusPlusWrapperX();
	  const int N_PACKETS = 1200;
	  // With these fec params "testWithoutPacketLoss" is not possible
	  /*const std::vector<std::pair<unsigned int, unsigned int>> fecParams1 = {
		  {1, 0}, {1, 100},
		  {2, 0}, {2, 50}, {2, 100}
	  };
	  for (const auto &fecParam: fecParams1) {
		const auto k = fecParam.first;
		const auto p = fecParam.second;
		TestFEC::testWithoutPacketLossFixedPacketSize(k, p, N_PACKETS);
		TestFEC::testWithoutPacketLossFixedPacketSize(k, p, N_PACKETS);
	  }*/
	  // only test with FEC enabled
	  const std::vector<std::pair<unsigned int, unsigned int>> fecParams = {
		  {1, 200},
		  {2, 100}, {2, 200},
		  {4, 100}, {4, 200},
		  {6, 50}, {6, 100}, {6, 200},
		  {8, 50}, {8, 100}, {8, 200},
		  {10, 30}, {10, 50}, {10, 100},
		  {40, 30}, {40, 50}, {40, 100},
		  {100, 30}, {100, 40}, {100, 50}, {100, 60},
		  {120, 50}
	  };
	  for (const auto &fecParam: fecParams) {
		const auto k = fecParam.first;
		const auto p = fecParam.second;
		/*TestFEC::testWithoutPacketLossFixedPacketSize(k, p, N_PACKETS);
		TestFEC::testWithoutPacketLossDynamicPacketSize(k, p, N_PACKETS);*/
		TestFEC::testRxQueue(k, p);
		for (int dropMode = 1; dropMode < 2; dropMode++) {
		  //TestFEC::testWithPacketLossButEverythingIsRecoverable(k, p, N_PACKETS, dropMode);
		}
	  }
	  TestFEC::testWithoutPacketLossDynamicBlockSize();
	}
	if (test_mode == 0 || test_mode == 2) {
	  //
	  std::cout << "Testing Encryption\n";
	  TestEncryption::test(false);
	  TestEncryption::test(true);
	  //
	}
  } catch (std::runtime_error &e) {
	std::cerr << "Error: " << std::string(e.what());
	exit(1);
  }
  std::cout << "All Tests Passing\n";
  return 0;
}