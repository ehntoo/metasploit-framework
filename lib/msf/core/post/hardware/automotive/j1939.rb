# -*- coding: binary -*-
module Msf
class Post
module Hardware
module Automotive

module J1939

  # Sends a message via the j1939 bus
  # @param bus [String] bus name identifier
  # @param priority [Integer] priority of message (3 bits, 000 = Highest 111 = Lowest)
  # @param pgn [Integer] Message PGN
  # @param sdata [String] String of bytes to send
  # @param sa [Integer] Source Address
  # @param da [Integer] Destination Address (0xFF is broadcast)
  def send_j1939(bus, priority, pgn, sdata, sa=249, da=0xFF)
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    spriority = (priority << 26) & 0x1C000000
    spgn = (pgn << 8) & 0x03FFFF00
    ssa = sa & 0x000000FF
    id = spriority + spgn + ssa
    opt = { "pgn" => pgn, "da" => da }
    client.automotive.cansend(bus, id.to_s(16), sdata, opt)
  end

  def read_j1939(bus, opt={})
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    packets = client.automotive.candump(bus, opt)
    # Reformat returned packets to ensure J1939 metadata is included
    if packets.key? "Packets"
      packets["Packets"].each do |pkt|
        priority = (pkt["ID"] & 0x1C00000) >> 26
        pgn = (pkt["ID"] & 0x03FFFF00) >> 8
        sa = pkt["ID"] & 0x000000FF
        pkt["PRIORITY"] = priority
        pkt["PGN"] = pgn
        pkt["SA"] = sa
      end
    end
    return packets
  end

  # Request a PGN from a sepefic address
  # @param pgn [String] Hex value of the PGN
  # @param sa [String] Source address as Hex
  def request_pgn(bus, pgn, sa=0)
    unless client.automotive
      print_error("Not an automotive hwbridge session")
      return {}
    end
    bus = client.automotive.active_bus unless bus
    unless bus
      print_line("No active bus, use 'connect' or specify bus via the options")
      return {}
    end
    results = {}
    results["Packets"] = []
    send_j1939(bus, 6, 59904, pgn)
    packets = read_j1939(bus, {"filter_id" => sa, "maxpkts" => 20, "timeout" => 1000})
    if packets.key? "Packets"
      packets["Packets"].each do |pkt|
        if pkt["PGN"] == pgn
          results["Packets"] << pkt
        end
      end
    end
  end
  return  results
end

end
end
end
end
