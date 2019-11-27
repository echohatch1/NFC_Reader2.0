# Example of detecting and reading a block from a MiFare classic NFC card.
# Author: Tony DiCola & Roberto Laricchia
# MiFare Classic modification: Francesco Crisafulli
#
# Copyright (c) 2015 Adafruit Industries
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
This example shows connecting to the PN532 and writing & reading a mifare classic
type RFID tag
"""

import board
import busio
from digitalio import DigitalInOut
import time
from adafruit_pn532.adafruit_pn532 import MIFARE_CMD_AUTH_B
from adafruit_pn532.spi import PN532_SPI


# SPI connection:
spi = busio.SPI(board.SCK, board.MOSI, board.MISO)
cs_pin = DigitalInOut(board.D5)
pn532 = PN532_SPI(spi, cs_pin, debug=False)

ic, ver, rev, support = pn532.get_firmware_version()
print('Found PN532 with firmware version: {0}.{1}'.format(ver, rev))

# Configure PN532 to communicate with MiFare cards
pn532.SAM_configuration()

print('Listening for NFC card...')

key = b'\xFF\xFF\xFF\xFF\xFF\xFF'

while True:
    # Check if a card is available to read
    uid = pn532.read_passive_target()
    
    if uid != None:
        #print('Found card with UID:', [hex(i) for i in uid])
    
        try:
            authenticated = pn532.mifare_classic_authenticate_block(uid, 4, MIFARE_CMD_AUTH_B, key)


            try:
                #card text data must be in blocks 4 to 5 and be at least 7 character long (truncated after 7)
                
                block4 = pn532.mifare_classic_read_block(4)
                block5 = pn532.mifare_classic_read_block(5)


                #first 5 characters of text
                firstPart = block4[11:].decode()

                #characters 6 and 7 of text (can be changed)
                secondPart = block5[:2].decode()

                message = firstPart + secondPart

                print(message)
                
                time.sleep(2)
                    
                
            except ValueError:
                
                print("Card not formatted correctly. Text is either less than 7 characters or card isn't a Mifare Classic.")

        except TypeError:
            print("Authentication failed!")
