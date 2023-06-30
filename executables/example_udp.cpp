//
// Created by consti10 on 30.06.23.
//

#include "../src/WBStreamRx.h"
#include "../src/WBStreamTx.h"
#include "../src/WBTxRx.h"
#include "../src/wifibroadcast-spdlog.h"
#include "RandomBufferPot.hpp"

int main(int argc, char *const *argv) {
  std::string card = "wlxac9e17596103";
  int opt;
  while ((opt = getopt(argc, argv, "w:")) != -1) {
    switch (opt) {
      case 'w':
        card = optarg;
        break;
      default: /* '?' */
      show_usage:
        fprintf(
            stderr,
            "Local receiver: %s [-K rx_key] [-c client_addr] [-u udp_client_port] [-r radio_port] interface1 [interface2] ...\n",
            argv[0]);
        exit(1);
    }
  }
}