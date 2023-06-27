//
// Created by consti10 on 27.06.23.
//

#include "../src/TxRxInstance.h"
#include "RandomBufferPot.hpp"

int main(int argc, char *const *argv) {

  auto card="wlxac9e17596103";
  std::vector<std::string> cards{card};
  std::unique_ptr<TxRxInstance> tmp=std::make_unique<TxRxInstance>(cards);
  tmp->start_receiving();

  const auto randomBufferPot = std::make_unique<RandomBufferPot>(1000, 1024);

  while (true){
    for(int i=0;i<100;i++){
      auto dummy_packet=randomBufferPot->getBuffer(i);
      tmp->tx_inject_packet(0,dummy_packet->data(),dummy_packet->size());
      std::this_thread::sleep_for(std::chrono::milliseconds (500));
    }
  }
}