require 'pry'

class Pcap

  def initialize(file)
    @file = file
    @little_endian = hex(4) == "d4c3b2a1"
    @force_big = false
  end

  def force_big
    @force_big = true
    self
  end

  def fetch(count)
    bytes = @file.read(count)
    if @force_big
      @force_big = false
      return bytes
    end
    @little_endian ? bytes.reverse : bytes
  end

  def int(bits)
    map = { 8 => 'C', 16 => 'S>', 32 => 'L>', 64 => 'Q>' }
    fetch(bits / 8).unpack(map[bits]).first
  end

  def split(*bit_counts)
    total_bits = bit_counts.inject(&:+)
    bits = int(total_bits)

    pos = 0
    bit_counts.map do |bc|
      mask = 2 ** (total_bits - pos) - 1
      pos += bc
      (bits & mask) >> (total_bits - pos)
    end
  end

  def raw(count)
    fetch(count).split(//).map{ |b| b.unpack('C') }.flatten
  end

  def hex(count)
    raw(count).map{ |b| b.to_s(16) }.join
  end

  def binary(count)
    raw(count).map{ |b| b.to_s(2) }.join.rjust(count, "0")
  end

  def ip_address
    raw(4).join('.')
  end

end
