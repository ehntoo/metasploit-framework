class MetasploitModule < Msf::Post

  include Msf::Post::Hardware::RFTransceiver::RFTransceiver
  include Msf::Post::Hardware::RFTransceiver::NordicRF

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'NordicRF HID Sniffer',
        'Description'   => %q{
            This module interfaces with an HWBridge-connected NordicRF radio transceiver,
            to identify wireless HID devices and optional decode their communications.
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
      OptString.new('ADDRESS', [false, "Address to sniff.  If blank shows all"]),
      OptInt.new('CHANNEL', [false, "Only listen on a set channel.  If blank scans all.  Range: 2-83"]),
      OptString.new('BRAND', [false, "Specify brand to decode packets", "Logitech"]),
      OptInt.new('TIMEOUT', [false, "Timeout for sniffing in seconds", 20]),
      OptBool.new('LNA', [false, "Use builtin Low Noise Amp", true]),
      OptBool.new('CRC', [false, "User Packet CRC (ESB Mode)", true]),
      OptInt.new('INDEX', [false, "USB Index to use", 0])
    ], self.class)

  end

  # Given an array of packets, attempt to fingerprint the device
  def fingerprint_device(packets)
    packets.each do |pkt|
      fp = fingerprint_hid_device(pkt)
      return fp if fp and fp.size > 0
    end
    ""
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
    channels = (2..83).to_a
    channel_idx = 0
    channel = channels[channel_idx]
    if datastore['CHANNEL']
      unless channels.include? datastore['CHANNEL']
        print_error("Channels need to be from 2 to 83")
        return
      end
      channel = datastore['CHANNEL']
    end
    devices = {}
    start_time = Time.now()
    last_tune = Time.now()
    dwell_time = 0.1
    enable_crc if datastore['CRC'] == true
    enable_lna if datastore['LNA'] == true
    set_mode("rx")
    set_channel(channel)
    print_status("Listening for wireless HID devices for #{datastore['TIMEOUT']} seconds...")
    while Time.now() - start_time < datastore['TIMEOUT']
      unless datastore['CHANNEL']
        if Time.now() - last_tune > dwell_time
          channel_idx += 1
          channel_idx = 0 if channel_idx > channels.size
          channel = channels[channel_idx]
          set_channel(channel)
          last_tune = Time.now()
        end
      end
      packet = rfrecv()
      data = packet["data"]
      if data.size >= 5
        address = data[0, 5]
        payload = data[5, data.size - 5]
        if devices.key? address
          unless devices[address]["Channels"].include? channel
            devices[address]["Channels"] << channel
          end
          unless devices[address]["Payloads"].include? payload
            devices[address]["Payloads"] << payload
          end
          devices[address]["Seen"] = Time.now()
          devices[address]["Count"] += 1
        else
          devices[address] = {}
          devices[address]["Payloads"] = [ payload ]
          devices[address]["Channels"] = [ channel ]
          devices[address]["Seen"] = Time.now()
          devices[address]["Count"] = 1
          print_status("New Device: Address: #{address.each_byte.map { |b| sprintf("%02X", b) }.join(':')} Channel: #{channel} Payload: #{payload.each_byte.map { |b| sprintf("%02X", b) }.join(':')}")
        end
      end
    end
    print_status("Summary:")
    if devices.size == 0
      print_status("  No devices found.  This is common when scanning lots of channels, you may just want to rerun or increase your timeout")
    else
      print_status(" ADDRESS           CHANNELS   COUNT  SEEN                        TYPE")
      print_status(" ---------------   --------   -----  -------------------------   -------------")
      devices.each_key do |address|
         buf = sprintf("%15s  %10s   %5s  %20s   %s",
           address.each_byte.map { |b| sprintf("%02X", b) }.join(':'),
           devices[address]["Channels"].join(','),
           devices[address]["Count"],
           devices[address]["Seen"],
           fingerprint_device(devices[address]["Payloads"]))
         print_status(buf)
      end  
    end
  end

end
