#!/bin/bash

# Simple script to set a default wifi frequency on a card in monitor mode
#

# wifi card is first param
MY_WIFI_CARD=$1

# Should work on most card(s) - 5180Mhz at HT20 (20Mhz channel width)
MY_WIFI_FREQ_MHZ=5180

echo "Setting $MY_WIFI_CARD to $MY_WIFI_FREQ_MHZ"

sudo iw dev $MY_WIFI_CARD set freq $MY_WIFI_FREQ_MHZ HT20