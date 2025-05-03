# Copyright (c) gzip
# Licensed under CC BY-NC-SA 4.0 https://creativecommons.org/licenses/by-nc-sa/4.0/deed.en

import math, os, sys, time, argparse

DEBUG = False
OUTDIR = ""

def shiftLeft(val, count):
  return val << count

def shiftRight(val, count):
  return val >> count

def to16bit(hi, lo):
  return (hi << 8) + lo

def bytesToHex(bytes):
  return ' '.join(list(map(lambda v: f'{v:02X}', bytes)))

def k(val):
  return val * 1024

PRG_SIZE = [k(512), k(256), k(128), k(64), k(32), k(16), k(8), k(2048)]
CHR_SIZE = [k(256), k(128), k(64),  None,  k(32), k(16), k(8), None]

PRG_SIZE_HDR = [0x20, 0x10, 0x08, 0x04, 0x02, 0x01, None, 0x80]
CHR_SIZE_HDR = [0x20, 0x10, 0x08, None, 0x04, 0x02, 0x01, None]

PRG_SIZE_K = ["512k", "256k", "128k", "64k", "32k", "16k", "8k", "2048k"]
CHR_SIZE_K = ["256k", "128k", "64k", "Invalid", "32k", "16k", "8k", "Invalid"]

# look for mapper specific signatures (not guaranteed)
def guess_mapper(data):

  if data.find(b'\x8D\x00\x41') != -1: # STA $4100
    mapper = 256
  elif data.find(b'\x8D\x00\xE0\x4A') != -1 or \
       data.find(b'\x8D\x00\xC0\x4A') != -1 or \
       data.find(b'\x8D\x00\xA0\x4A') != -1:     # STA $E000/$C000/$A000 LSR
    mapper = 1
  elif data.find(b'\x8D\x01\x80') != -1: # STA $8001
    mapper = 4
  else:
    mapper = 0
  return mapper

def write_header(handle, bank, mapper):

  handle.write(b'NES\x1A')
  handle.write(bank["prgSizeHeader"].to_bytes())
  handle.write(bank["chrSizeHeader"].to_bytes())

  mirror = bank["mirror"]

  if mapper == 256:
    handle.write(mirror.to_bytes())
    handle.write(b"\x0A\x01")
    handle.write(b"\0"*7)
  else:
    if mapper == 4:
      mirror ^= mirror
    handle.write((mapper << 4 | mirror).to_bytes())
    handle.write(b"\0"*9)

def write_rom(file_handle, title, bank, outdir):

  file_handle.seek(bank["prgAddr"])
  prgData = file_handle.read(bank["prgSize"])
  file_handle.seek(bank["chrAddr"])
  chrData = file_handle.read(bank["chrSize"])

  mapper = guess_mapper(prgData)

  file_path = os.path.join(outdir, title) + ".nes"
  print ("extracting " + file_path + (" (mapper " + str(mapper) + ") from data:" if DEBUG else ""))
  if DEBUG:
    print ("    " + bank["bytes"] + " :: " + str(bank["prgSizeK"]) + " PRG @ " + bank["prgAddrHex"] + " / " + str(bank["chrSizeK"]) + " CHR @ " + bank["chrAddrHex"])
  with open(file_path, "wb") as rom_handle:
    write_header (rom_handle, bank, mapper)
    rom_handle.write(prgData)
    rom_handle.write(chrData)
    rom_handle.close()

def process_titles(file_handle, separator, end, max_titles):

  title_len = 0
  titles = []

  while (title_len < 30):
    title_len = 0
    title = ""
    byte = file_handle.read(1)
    if (int.from_bytes(byte) == end):
      break
    while (int.from_bytes(byte) != separator):
      title += byte.decode('utf-8')
      byte = file_handle.read(1)
      title_len += 1
      if (title_len == 30):
        break
    if (title_len < 30):
      titles.append(title)
      if (len(titles) >= max_titles):
        break
  return titles

def process_banks(file_handle, fn, size, count):

  data = []

  while (len(data) < count):
    bytes = file_handle.read(size)
    info = fn(bytes)
    if info:
      data.append(info)
    else:
      break
  return data

# indices:
#    outerBank - the value written to $4100
#    prgSize   - the value written to $410B
#    chrBank0  - the value written to $2018
#    chrBank1  - the value written to $201A
#    prgBank0  - the value written to $4107
#    mirror    - the value written to $4106 or $A000
def process_bank(bytes, indices, chrOffset):

  data = {}
  data["bytes"] = bytesToHex(bytes)

  # PRG info
  data["prgAddr"] = shiftLeft(to16bit(shiftRight(bytes[indices["outerBank"]], 4), bytes[indices["prgBank0"]]), 13)
  data["prgAddrHex"] = f'{data["prgAddr"]:07X}'
  prgSizeIndex = bytes[indices["prgSize"]]
  data["prgSize"] = PRG_SIZE[prgSizeIndex]
  data["prgSizeK"] = PRG_SIZE_K[prgSizeIndex]
  data["prgSizeHeader"] = PRG_SIZE_HDR[prgSizeIndex]

  # CHR info (chrOffset seems to vary by device)
  data["chrAddr"] = chrOffset + shiftLeft(to16bit(shiftRight(bytes[indices["chrBank0"]], 4), bytes[indices["chrBank1"]] & 0b11111000), 10)
  data["chrAddrHex"] = f'{data["chrAddr"]:07X}'
  chrSizeIndex = bytes[indices["chrBank1"]] & 0b00000111
  data["chrSize"] = CHR_SIZE[chrSizeIndex]
  data["chrSizeK"] = CHR_SIZE_K[chrSizeIndex]
  data["chrSizeHeader"] = CHR_SIZE_HDR[chrSizeIndex]

  data["mirror"] = bytes[indices["mirror"]] ^ 1
  return data

def process_retro_game_box_bank(bytes):

  indices = {"outerBank":0, "prgSize":1, "chrBank0":2, "chrBank1":3, "prgBank0":4, "prgBank1":5, "mirror": 6}
  chrOffset = (bytes[indices["outerBank"]] & 0x02) * 0x200000
  data = process_bank(bytes, indices, chrOffset)
  return data

def process_retrogame_bank(bytes):

  if bytes[0] == 0xFF:
    return None

  indices = {"outerBank":0, "chrBank0":1, "chrBank1":2, "prgSize":3, "prgBank0":4, "prgBank1":5, "prgBank2":6, "prgBank3":7, "mirror": 8}
  chrOffset = (bytes[indices["outerBank"]] & 0b00001111) * 0x200000
  data = process_bank(bytes, indices, chrOffset)
  return data

def process_mini_arcade_bank(bytes):

  if bytes[0] == 0xFF:
    return None

  newbytes = bytearray(bytes)

  indices = {"prgSize":0, "chrBank0":1, "chrBank1":2, "outerBank":5,
             "prgBank0":7, "prgBank1":8, "prgBank2":9, "prgBank3":10, "mirror": 11}

  chrBank0 = math.floor(bytes[6]/64)
  if (bytes[7] & 1):
    chrBank0 = (chrBank0 * 2 + 1) << 4
  else:
    chrBank0 = chrBank0 << 4

  # (%64) ASL << 2 $0206 (#$32 to =#$C8*) ORA $0311 (#$06) (=#$CE) STA $201A
  chrBank1 = ((bytes[6] % 64) << 2) | bytes[2]

  # reassign byte values
  newbytes[indices["chrBank0"]] = chrBank0
  newbytes[indices["chrBank1"]] = chrBank1

  # (%02) (=#$00~) STA $0207  ORA $0312  STA $4100 (=#$30)
  # (%32) STA $0205  LSR (=#$03)  ASL << 4 (=#$30~) STA $0312
  outerBank = (((bytes[5] % 32) >> 1) << 4) | math.floor(bytes[7] / 2)
  newbytes[indices["outerBank"]] = outerBank

  # set up PRG banks
  # mimic LSR ROR
  prgBank0 = (0b10000000 if (bytes[5] & 1) else 0) | (bytes[4] >> 1)
  if bytes[0] >= 5:
    prgBank2 = prgBank0
    prgBank1 = prgBank3 = prgBank0 + 1
  else:
    prgBank1 = prgBank0 + 1
    prgBank2 = prgBank0 + 2
    prgBank3 = prgBank0 + 3

  # reassign byte values
  newbytes[indices["prgBank0"]] = prgBank0
  newbytes[indices["prgBank1"]] = prgBank1
  newbytes[indices["prgBank2"]] = prgBank2
  newbytes[indices["prgBank3"]] = prgBank3

  chrOffset = (outerBank & 0b00001111) * 0x200000
  data = process_bank(newbytes, indices, chrOffset)
  return data

def set_args(args, defaults):

  keys = vars(args).keys()
  for key in defaults:
    if not key in keys or args.__dict__[key] == None:
      args.__dict__[key] = defaults[key]

def export():

  parser, args = parse_args()

  error = ""

  if args.debug:
    globals()['DEBUG'] = True

  if args.device == "retro_game_box":
    set_args(args, {
      "titles": 0x6A1BC,
      "banks": 0x6E000,
      "separator": 255,
      "end": 0,
      "size": 8
    })
    args.process_fn = process_retro_game_box_bank

  elif args.device == "retrogame":
    set_args(args, {
      "titles": 0x7C010,
      "banks": 0x7B000,
      "separator": 0,
      "end": 0,
      "size": 9,
      "count": 128
    })
    args.process_fn = process_retrogame_bank

  elif args.device == "jl3000":
    set_args(args, {
      "titles": 0x7BA6A,
      "banks": 0x7A900,
      "separator": 0,
      "end": 255,
      "size": 9
    })
    args.process_fn = process_retrogame_bank

  elif args.device == "mini_arcade":
    set_args(args, {
      "titles": 0x6867E,
      "banks": 0x6C1E0,
      "separator": 255,
      "end": 255,
      "size": 12,
      "count": 240
    })
    args.process_fn = process_mini_arcade_bank

  if args.filename == None:
    error += f'\nError: Filename is required!'
  elif not os.path.isfile(args.filename):
    error += f'\nError: File "{args.filename}" not found!'
    args.filename = ""

  if args.titles == None:
    error += f'\nError: Titles address is required!'

  if args.banks == None:
    error += f'\nError: Banks address is required!'

  if args.size == None:
    error += f'\nError: Entry size is required!'

  if args.separator == None:
    error += f'\nError: Title separator character is required!'

  if args.end == None:
    error += f'\nError: Title end character is required!'

  if args.outdir:
    if not os.path.isdir(args.outdir):
      os.makedirs(args.outdir)
  else:
    error += f'\nError: Outdir is required!'

  if args.count == None:
    args.count = 1000

  if args.outdir and args.filename and args.titles and args.banks and args.size:
    with open(args.filename, "rb") as file_handle:

      file_handle.seek(args.titles)
      titles = process_titles(file_handle, args.separator, args.end, args.count)

      file_handle.seek(args.banks)
      banks = process_banks(file_handle, args.process_fn, args.size, len(titles))

      for b in range(len(banks)):
        write_rom(file_handle, titles[b], banks[b], args.outdir)

  else:
    print ('\n')
    parser.print_help()

  if error:
    print (f'{error}\n')

def dec(val):
  return int(val, 16)

def parse_args():

    parser = argparse.ArgumentParser(description="Extracts roms from a multicart dump.", add_help=False, epilog='Pass the required arguments to begin parsing roms.')

    parser.add_argument('--help', action="help")
    parser.add_argument('-f', '--filename', help='Input filename.')
    parser.add_argument('-t', '--titles', help='Address of title information, e.g. 0xA03F.', type=dec)
    parser.add_argument('-b', '--banks', help='Address of bank information, e.g. 0x6A000.', type=dec)
    parser.add_argument('-z', '--size', help='Size of each bank data entry, e.g. 9.', type=int)
    parser.add_argument('-s', '--separator', help='Character used to separate titles, e.g. 255.')
    parser.add_argument('-e', '--end', help='Character used to end titles, e.g. 0.', type=int)
    parser.add_argument('-d', '--device', help='Device name (automatically sets values for the required arguments).', choices=["jl3000", "mini_arcade", "retro_game_box", "retrogame"])
    parser.add_argument('-c', '--count', help='Max number of roms to parse, e.g. 10.', type=int)
    parser.add_argument('-o', '--outdir', help='Output directory.')
    parser.add_argument('-g', '--debug', help='Enable debug output.', action='store_true')

    args = parser.parse_args()

    return parser, args

if __name__ == "__main__":
    export()
