# -*- coding: binary -*-
module Msf
class Post
module Hardware
module RFTransceiver

module USB_HID

# 7 Supports DuckyScript syntax
#  Array is [ hid, mod ]
USB_KEYBOARD_HID = {
	'a' => [0x04, 0], #	Keyboard a
	'A' => [0x04, 2], #	Keyboard A
	'b' => [0x05, 0], #	Keyboard b
	'B' => [0x05, 2], #	Keyboard B
	'c' => [0x06, 0], #	Keyboard c
	'C' => [0x06, 2], #	Keyboard C
	'd' => [0x07, 0], #	Keyboard d
	'D' => [0x07, 2], #	Keyboard D
	'e' => [0x08, 0], #	Keyboard e
	'E' => [0x08, 2], #	Keyboard E
	'f' => [0x09, 0], #	Keyboard f
	'F' => [0x09, 2], #	Keyboard F
	'g' => [0x0A, 0], #	Keyboard g
	'G' => [0x0A, 2], #	Keyboard G
	'h' => [0x0B, 0], #	Keyboard h
	'H' => [0x0B, 2], #	Keyboard H
	'i' => [0x0C, 0], #	Keyboard i
	'I' => [0x0C, 2], #	Keyboard I
	'j' => [0x0D, 0], #	Keyboard j
	'J' => [0x0D, 2], #	Keyboard J
	'k' => [0x0E, 0], #	Keyboard k
	'K' => [0x0E, 2], #	Keyboard K
	'l' => [0x0F, 0], #	Keyboard l
	'L' => [0x0F, 2], #	Keyboard L
	'm' => [0x10, 0], #	Keyboard m
	'M' => [0x10, 2], #	Keyboard M
	'n' => [0x11, 0], #	Keyboard n
	'N' => [0x11, 2], #	Keyboard N
	'o' => [0x12, 0], #	Keyboard o
	'O' => [0x12, 2], #	Keyboard O
	'p' => [0x13, 0], #	Keyboard p
	'P' => [0x13, 2], #	Keyboard P
	'q' => [0x14, 0], #	Keyboard q
	'Q' => [0x14, 2], #	Keyboard Q
	'r' => [0x15, 0], #	Keyboard r
	'R' => [0x15, 2], #	Keyboard R
	's' => [0x16, 0], #	Keyboard s
	'S' => [0x16, 2], #	Keyboard S
	't' => [0x17, 0], #	Keyboard t
	'T' => [0x17, 2], #	Keyboard T
	'u' => [0x18, 0], #	Keyboard u
	'U' => [0x18, 2], #	Keyboard U
	'v' => [0x19, 0], #	Keyboard v
	'V' => [0x19, 2], #	Keyboard V
	'w' => [0x1A, 0], #	Keyboard w
	'W' => [0x1A, 2], #	Keyboard W
	'x' => [0x1B, 0], #	Keyboard x
	'X' => [0x1B, 2], #	Keyboard X
	'y' => [0x1C, 0], #	Keyboard y
	'Y' => [0x1C, 2], #	Keyboard Y
	'z' => [0x1D, 0], #	Keyboard z
	'Z' => [0x1D, 2], #	Keyboard Z
	'1' => [0x1E, 0], #	Keyboard 1
	'!' => [0x1E, 2], #	Keyboard !
	'2' => [0x1F, 0], #	Keyboard 2
	'@' => [0x1F, 2], #	Keyboard @
	'3' => [0x20, 0], #	Keyboard 3
	'#' => [0x20, 2], #	Keyboard #
	'4' => [0x21, 0], #	Keyboard 4
	'$' => [0x21, 2], #	Keyboard $
	'5' => [0x22, 0], #	Keyboard 5
	'%' => [0x22, 2], #	Keyboard %
	'6' => [0x23, 0], #	Keyboard 6
	'^' => [0x23, 2], #	Keyboard ^
	'7' => [0x24, 0], #	Keyboard 7
	'&' => [0x24, 2], #	Keyboard &
	'8' => [0x25, 0], #	Keyboard 8
	'*' => [0x25, 2], #	Keyboard *
	'9' => [0x26, 0], #	Keyboard 9
	'(' => [0x26, 2], #	Keyboard (
	'0' => [0x27, 0], #	Keyboard 0
	')' => [0x27, 2], #	Keyboard )
	'ENTER' => [0x28, 0], #	Keyboard Return (ENTER)
	'\r' => [0x28, 0], #	Keyboard Return (ENTER)
	'ESCAPE' => [0x29, 0], #	Keyboard ESCAPE
	'\e' => [0x29, 0], #	Keyboard ESCAPE
	'DELETE' => [0x2A, 0], #	Keyboard DELETE (Backspace)
	'\b' => [0x2A, 0], #	Keyboard DELETE (Backspace)
	'TAB' => [0x2B, 0], #	Keyboard Tab
	'\t' => [0x2B, 0], #	Keyboard Tab
	'SPACE' => [0x2C, 0], #	Keyboard Spacebar
	' ' => [0x2C, 0], #	Keyboard Spacebar
	'-' => [0x2D, 0], #	Keyboard -
	'_' => [0x2D, 2], #	Keyboard (underscore)
	'=' => [0x2E, 0], #	Keyboard =
	'+' => [0x2E, 2], #	Keyboard +
	'[' => [0x2F, 0], #	Keyboard [
	'{' => [0x2F, 2], #	Keyboard {
	']' => [0x30, 0], #	Keyboard ]
	'}' => [0x30, 2], #	Keyboard }
	'\\' => [0x31, 0], #	Keyboard \
	'|' => [0x31, 2], #	Keyboard |
	'NONUS_#' => [0x32, 0], #	Keyboard Non-US #
	'NONUS_~' => [0x32, 2], #	Keyboard Non-US ~
	';' => [0x33, 0], #	Keyboard ;
	':' => [0x33, 2], #	Keyboard :
	'\'' => [0x34, 0], #	Keyboard '
	'"' => [0x34, 2], #	Keyboard "
	'`' => [0x35, 0], #	Keyboard Grave Accent and Tilde
	'~' => [0x35, 2], #	Keyboard Grave Accent and Tilde
	',' => [0x36, 0], #	Keyboard ,
	'<' => [0x36, 2], #	Keyboard <
	'.' => [0x37, 0], #	Keyboard .
	'>' => [0x37, 2], #	Keyboard >
	'/' => [0x38, 0], #	Keyboard /
	'?' => [0x38, 2], #	Keyboard ?
	'CAPSLOCK' => [0x39, 0], #	Keyboard Caps Lock
	'F1' => [0x3A, 0], #	Keyboard F1
	'F2' => [0x3B, 0], #	Keyboard F2
	'F3' => [0x3C, 0], #	Keyboard F3
	'F4' => [0x3D, 0], #	Keyboard F4
	'F5' => [0x3E, 0], #	Keyboard F5
	'F6' => [0x3F, 0], #	Keyboard F6
	'F7' => [0x40, 0], #	Keyboard F7
	'F8' => [0x41, 0], #	Keyboard F8
	'F9' => [0x42, 0], #	Keyboard F9
	'F10' => [0x43, 0], #	Keyboard F10
	'F11' => [0x44, 0], #	Keyboard F11
	'F12' => [0x45, 0], #	Keyboard F12
	'PRINTSCREEN' => [0x46, 0], #	Keyboard PrintScreen
	'SCROLLLOCK' => [0x47, 0], #	Keyboard Scroll Lock
	'PAUSE' => [0x48, 0], #	Keyboard Pause
	'INSERT' => [0x49, 0], #	Keyboard Insert
	'HOME' => [0x4A, 0], #	Keyboard Home
	'PAGEUP' => [0x4B, 0], #	Keyboard PageUp
	'DEL' => [0x4C, 0], #	Keyboard Delete Forward
	'END' => [0x4D, 0], #	Keyboard End
	'PAGEDOWN' => [0x4E, 0], #	Keyboard PageDown
	'RIGHTARROW' => [0x4F, 0], #	Keyboard RightArrow
	'LEFTARROW' => [0x50, 0], #	Keyboard LeftArrow
	'DOWNARROW' => [0x51, 0], #	Keyboard DownArrow
	'UPARRAOW' => [0x52, 0], #	Keyboard UpArrow
	'NUMLOCK' => [0x53, 0], #	Keypad Num Lock and Clear
	'KEY_/' => [0x54, 0], #	Keypad /
	'KEY_*' => [0x55, 0], #	Keypad *
	'KEY_-' => [0x56, 0], #	Keypad -
	'KEY_+' => [0x57, 0], #	Keypad +
	'KEY_ENTER' => [0x58, 0], #	Keypad ENTER
	'KEY_1' => [0x59, 0], #	Keypad 1 and End
	'KEY_2' => [0x5A, 0], #	Keypad 2 and Down Arrow
	'KEY_3' => [0x5B, 0], #	Keypad 3 and PageDn
	'KEY_4' => [0x5C, 0], #	Keypad 4 and Left Arrow
	'KEY_5' => [0x5D, 0], #	Keypad 5
	'KEY_6' => [0x5E, 0], #	Keypad 6 and Right Arrow
	'KEY_7' => [0x5F, 0], #	Keypad 7 and Home
	'KEY_8' => [0x60, 0], #	Keypad 8 and Up Arrow
	'KEY_9' => [0x61, 0], #	Keypad 9 and PageUp
	'KEY_0' => [0x62, 0], #	Keypad 0 and Insert
	'KEY_.' => [0x63, 0], #	Keypad . and Delete
	'NONUS_\\' => [0x64, 0], #	Keyboard Non-US \
	'NONUS_|' => [0x64, 2], #	Keyboard Non-US |
	'APPLICATION' => [0x65, 0], #	Keyboard Application
	'POWER' => [0x66, 0], #	Keyboard Power
	'KEY_=' => [0x67, 0], #	Keypad =
	'F13' => [0x68, 0], #	Keyboard F13
	'F14' => [0x69, 0], #	Keyboard F14
	'F15' => [0x6A, 0], #	Keyboard F15
	'F16' => [0x6B, 0], #	Keyboard F16
	'F17' => [0x6C, 0], #	Keyboard F17
	'F18' => [0x6D, 0], #	Keyboard F18
	'F19' => [0x6E, 0], #	Keyboard F19
	'F20' => [0x6F, 0], #	Keyboard F20
	'F21' => [0x70, 0], #	Keyboard F21
	'F22' => [0x71, 0], #	Keyboard F22
	'F23' => [0x72, 0], #	Keyboard F23
	'F24' => [0x73, 0], #	Keyboard F24
	'EXECUTE' => [0x74, 0], #	Keyboard Execute
	'HELP' => [0x75, 0], #	Keyboard Help
	'MENU' => [0x76, 0], #	Keyboard Menu
	'SELECT' => [0x77, 0], #	Keyboard Select
	'STOP' => [0x78, 0], #	Keyboard Stop
	'AGAIN' => [0x79, 0], #	Keyboard Again
	'UNDO' => [0x7A, 0], #	Keyboard Undo
	'CUT' => [0x7B, 0], #	Keyboard Cut
	'COPY' => [0x7C, 0], #	Keyboard Copy
	'PASTE' => [0x7D, 0], #	Keyboard Paste
	'FIND' => [0x7E, 0], #	Keyboard Find
	'MUTE' => [0x7F, 0], #	Keyboard Mute
	'VOLUMEUP' => [0x80, 0], #	Keyboard Volume Up
	'VOLUMEDOWN' => [0x81, 0], #	Keyboard Volume Down
	'LOCKINGCAPSLOCK' => [0x82, 0], #	Keyboard Locking Caps Lock
	'LOCKINGNUMLOCK' => [0x83, 0], #	Keyboard Locking Num Lock
	'LOCKINGSCROLLLOCK' => [0x84, 0], #	Keyboard Locking Scroll Lock
	'KEY_COMMA' => [0x85, 0], #	Keypad Comma
	'KEY_EQUAL' => [0x86, 0], #	Keypad Equal Sign
	'KEY_INT1' => [0x87, 0], #	Keyboard International1
	'KEY_INT2' => [0x88, 0], #	Keyboard International2
	'KEY_INT3' => [0x89, 0], #	Keyboard International3
	'KEY_INT4' => [0x8A, 0], #	Keyboard International4
	'KEY_INT5' => [0x8B, 0], #	Keyboard International5
	'KEY_INT6' => [0x8C, 0], #	Keyboard International6
	'KEY_INT7' => [0x8D, 0], #	Keyboard International7
	'KEY_INT8' => [0x8E, 0], #	Keyboard International8
	'KEY_INT9' => [0x8F, 0], #	Keyboard International9
	'KEY_LANG1' => [0x90, 0], #	Keyboard LANG1
	'KEY_LANG2' => [0x91, 0], #	Keyboard LANG2
	'KEY_LANG3' => [0x92, 0], #	Keyboard LANG3
	'KEY_LANG4' => [0x93, 0], #	Keyboard LANG4
	'KEY_LANG5' => [0x94, 0], #	Keyboard LANG5
	'KEY_LANG6' => [0x95, 0], #	Keyboard LANG6
	'KEY_LANG7' => [0x96, 0], #	Keyboard LANG7
	'KEY_LANG8' => [0x97, 0], #	Keyboard LANG8
	'KEY_LANG9' => [0x98, 0], #	Keyboard LANG9
	'ALT_ERASE' => [0x99, 0], #	Keyboard Alternate Erase
	'SYSREQ' => [0x9A, 0], #	Keyboard SysReq/Attention
	'CANCEL' => [0x9B, 0], #	Keyboard Cancel
	'CLEAR' => [0x9C, 0], #	Keyboard Clear
	'PRIOR' => [0x9D, 0], #	Keyboard Prior
	'RETURN' => [0x9E, 0], #	Keyboard Return
	'SEPERATOR' => [0x9F, 0], #	Keyboard Separator
	'OUT' => [0xA0, 0], #	Keyboard Out
	'OPER' => [0xA1, 0], #	Keyboard Oper
	'CLEARAGAIN' => [0xA2, 0], #	Keyboard Clear/Again
	'CRSEL' => [0xA3, 0], #	Keyboard CrSel/Props
	'EXSEL' => [0xA4, 0], #	Keyboard ExSel
	'LEFTCONTROL' => [0xE0, 0], #	Keyboard LeftControl
	'LEFTSHIFT' => [0xE1, 0], #	Keyboard LeftShift
	'LEFTALT' => [0xE2, 0], #	Keyboard LeftAlt
	'LEFTGUI' => [0xE3, 0], #	Keyboard Left GUI
	'RIGHTCONTROL' => [0xE4, 0], #	Keyboard RightControl
	'RIGHTSHIFT' => [0xE5, 0], #	Keyboard RightShift
	'RIGHTALT' => [0xE6, 0], #	Keyboard RightAlt
	'RIGHTGUI' => [0xE7, 0], #	Keyboard Right GUI
        '':           [0, 0],
        'ALT':        [0, 4],
        'SHIFT':      [0, 2],
        'CTRL':       [0, 1],
        'GUI':        [0, 8]
}

  # Returns a hid for a given character or keyword
  # @param char [String]. Character or a keyword
  # @return [Hash] Returns { "hid": "mod":, "char""; "sleep" }
  def char_to_hid(char)
    key = blank_key
    unless USB_KEYBOARD_HID.key? char
      return key
    end
    hid = USB_KEYBOARD_HID[char]
    key["hid"] = hid[0]
    key["mod"] = hid[1]
    key["char"] = char
    key
  end

  # Converts a string to keyboard hids.  Does not support keywords
  # @param str [String] String to conver to an array of hids
  # @return [Array] of Hashes that are [ [ hid, mod], [hid, mod] ... ]
  def string_to_hids(str)
    hids = []
    str.each_byte do |i|
      hids << char_to_hid(i.chr)
    end
    hids
  end

  # Returns a blank key structure
  # @return [Hash] Blank key values for: mod, hid, char and sleep
  def blank_key
    key = { "mod" => 0, "hid" => 0, "char" => 0, "sleep" => 0 }
    key
  end


end

end
end
end
end
