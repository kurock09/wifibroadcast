#!/bin/bash

# Simple script to enable monitor mode and set same frequency all together
# Intended to be used with executables/example_hello.cpp

# !! Need to pass card
MY_WIFI_CARD=$1


sh ./enable_monitor_mode.sh $MY_WIFI_CARD

sh ./set_default_freq.sh $MY_WIFI_CARD


