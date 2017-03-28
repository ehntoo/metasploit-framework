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
