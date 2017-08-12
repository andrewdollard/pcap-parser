require_relative 'pcap'

class Parser

  attr_reader :pcap

  TARGET_IP = "192.168.0.101"

  def initialize
    @result = {}
  end

  def parse(filename)
    File.open(filename) do |file|
      @pcap = Pcap.new(file)

      puts "===File Header==="
      puts "Version: #{pcap.hex(2).to_i}.#{pcap.hex(2).to_i}"
      puts "Time Zone offset: #{pcap.hex(4)}"
      puts "Time stamp accuracy: #{pcap.hex(4)}"
      puts "Snapshot length: #{pcap.int(32)}"
      puts "Link-layer header type: #{pcap.hex(4)}"

      while (!file.eof?)
        puts fetch_packet
      end

      return @result.keys.sort.map { |key| @result[key] }.flatten
    end
  end

  def fetch_packet
    puts "\n===PCAP Packet==="
    seconds = @pcap.int(32)
    microseconds = @pcap.int(32)
    puts "Timestamp: #{Time.at(seconds, microseconds)}"
    captured_length = @pcap.int(32)
    original_length = @pcap.int(32)
    puts "Captured length: #{captured_length}"
    puts "Original length: #{original_length}"
    fetch_ethernet_frame(pcap, captured_length)
  end

  def fetch_ethernet_frame(pcap, length)
    puts "\n===Ethernet Frame==="
    # puts "Preamble: #{pcap.hex(8)}"
    puts "Destination MAC: #{pcap.hex(6)}"
    puts "Source MAC: #{pcap.hex(6)}"
    puts "Type: #{pcap.hex(2)}"
    fetch_ip(pcap, length - 14)
    # puts "FCS: #{pcap.hex(4)}"
  end

  def as_bin(val, len)
    val.to_s(2).rjust(len, "0")
  end

  def fetch_ip(pcap, length)
    puts "\n===IP Packet==="
    version, ihl = @pcap.split(4,4)
    puts "Version: #{version}"
    puts "Internet Header Length: #{ihl}"
    dscp, ecn = @pcap.split(6,2)
    puts "DSCP: #{dscp}"
    puts "ECN: #{ecn}"
    total_length = @pcap.force_big.int(16)
    puts "Total length: #{total_length}"
    puts "ID: #{pcap.force_big.hex(2)}"
    flags, offset = @pcap.force_big.split(3, 13)
    puts "Flags: #{as_bin(flags, 3)}"
    puts "Offset: #{offset}"
    puts "TTL: #{pcap.int(8)}"
    puts "Protocol: #{pcap.int(8)}"
    puts "Header checksum: #{pcap.force_big.int(16)}"
    source_ip = @pcap.force_big.ip_address
    puts "Source IP: #{source_ip}"
    destination_ip = @pcap.force_big.ip_address
    puts "Destination IP: #{destination_ip}"
    if source_ip = TARGET_IP
      store(*fetch_tcp(pcap, length - ihl * 4))
    else
      fetch_tcp(pcap, length - ihl * 4)
    end
    ""
  end

  def fetch_tcp(pcap, length)
    puts "\n===TCP Packet==="
    puts "Source port: #{pcap.force_big.int(16)} Destination port: #{pcap.force_big.int(16)}"
    sequence_number = @pcap.force_big.int(32)
    puts "Sequence #: #{sequence_number}"
    puts "Ack #: #{pcap.force_big.int(32)}"
    data_offset, reserved, flags = @pcap.force_big.split(4,3, 9)
    puts "Data offset: #{data_offset} Reserved: #{reserved} Flags: #{as_bin(flags, 9)} Window: #{pcap.force_big.int(16)}"
    puts "Checksum: #{pcap.force_big.int(16)} Urgent pointer: #{pcap.force_big.int(16)}"

    options = (data_offset - 5).times.map { @pcap.force_big.int(32) }
    puts "Options: #{options}"

    data = @pcap.force_big.raw(length - data_offset * 4).flatten
    [sequence_number, data]
  end

  def store(sequence_number, data)
    @result[sequence_number] = data
  end

end

parser = Parser.new
http = parser.parse('01-net.cap')

flag = false
last = ''
loop do
  chr = http.shift.chr
  print chr
  if chr == "\n" && last == "\r"
    break if flag
    flag = true
  else
    flag = false unless chr == "\r"
  end
  last = chr
end

File.open('image.jpg', 'w') { |f| f.write(http.pack('C*')) }
`open image.jpg`
