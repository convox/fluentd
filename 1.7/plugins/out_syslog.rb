require "openssl"
require "socket"
require "syslog_protocol"
require "uri"

module Fluent
  module Plugin
    class SyslogOutput < Fluent::Output
      Fluent::Plugin.register_output("syslog", self)

      config_param :url, :string, :default => nil

      config_param :facility, :string, :default => "user"
      config_param :severity, :string, :default => "debug"

      config_param :hostname_key, :string, :default => nil
      config_param :payload_key, :string, :default => "message"
      config_param :tag_key, :string, :default => nil

      def initialize
        super
      end

      def configure(conf)
        super

        raise Fluent::ConfigError.new("url required") if not conf["url"]

        @url = URI(conf["url"])
        @url.port ||= 514

        @facilty = conf["facility"]
        @severity = conf["severity"]
        @hostname_key = conf["hostname_key"]
        @payload_key = conf["payload_key"]
        @tag_key = conf["tag_key"]
      end

      def start
        super
      end

      def shutdown
        super
      end

      def format(tag, time, record)
        [tag, time, record].to_msgpack
      end

      def emit(tag, es, chain)
        chain.next

        es.each do |time, record|
          @sender ||= create_sender

          begin
            @sender.transmit(record[@payload_key].chomp!, {
              facility: @facility,
              severity: @severity,
              hostname: record[@hostname_key] || hostname,
              program: @tag_key ? record[@tag_key] : tag,
            })
          rescue
            @sender = nil
          end
        end
      end

      def create_sender
        case @url.scheme
        when "tcp"
          RemoteSyslogSender::TcpSender.new(@url.host, @url.port, whinyerrors: true, program: "convox")
        when "tcp+tls"
          RemoteSyslogSender::TcpSender.new(@url.host, @url.port, whinyerrors: true, program: "convox", tls: true, verify_mode: OpenSSL::SSL::VERIFY_NONE)
        when "udp"
          RemoteSyslogSender::UdpSender.new(@url.host, @url.port, whinyerrors: true, program: "convox")
        else
          raise Fluent::ConfigError.new("unknown scheme: #{@url.scheme}")
        end
      end
    end
  end
end

module RemoteSyslogSender
  class Sender
    # To suppress initialize warning
    class Packet < SyslogProtocol::Packet
      def initialize(*)
        super
        @time = nil
      end
    end

    attr_reader :socket
    attr_accessor :packet

    def initialize(remote_hostname, remote_port, options = {})
      @remote_hostname = remote_hostname
      @remote_port = remote_port
      @whinyerrors = options[:whinyerrors]
      @packet_size = options[:packet_size] || 1024

      @packet = Packet.new

      local_hostname = options[:hostname] || options[:local_hostname] || (Socket.gethostname rescue `hostname`.chomp)
      local_hostname = "localhost" if local_hostname.nil? || local_hostname.empty?
      @packet.hostname = local_hostname

      @packet.facility = options[:facility] || "user"
      @packet.severity = options[:severity] || "notice"
      @packet.tag = options[:tag] || options[:program] || "#{File.basename($0)}[#{$$}]"

      @socket = nil
    end

    def transmit(message, packet_options = nil)
      message.split(/\r?\n/).each do |line|
        begin
          next if line =~ /^\s*$/
          packet = @packet.dup
          if packet_options
            packet.tag = packet_options[:program] if packet_options[:program]
            packet.hostname = packet_options[:local_hostname] if packet_options[:local_hostname]
            %i(hostname facility severity tag).each do |key|
              packet.send("#{key}=", packet_options[key]) if packet_options[key]
            end
          end
          packet.content = line
          send_msg(packet.assemble(@packet_size))
        rescue
          if @whinyerrors
            raise
          else
            $stderr.puts "#{self.class} error: #{$!.class}: #{$!}\nOriginal message: #{line}"
          end
        end
      end
    end

    # Make this act a little bit like an `IO` object
    alias_method :write, :transmit

    def close
      @socket.close
    end

    private

    def send_msg(payload)
      raise NotImplementedError, "please override"
    end
  end

  class TcpSender < Sender
    class NonBlockingTimeout < StandardError; end

    def initialize(remote_hostname, remote_port, options = {})
      super
      @tls = options[:tls]
      @retry_limit = options[:retry_limit] || 3
      @retry_interval = options[:retry_interval] || 0.5
      @remote_hostname = remote_hostname
      @remote_port = remote_port
      @ssl_method = options[:ssl_method] || "TLSv1_2"
      @ca_file = options[:ca_file]
      @verify_mode = options[:verify_mode]
      @timeout = options[:timeout] || 600
      @timeout_exception = !!options[:timeout_exception]
      @exponential_backoff = !!options[:exponential_backoff]

      @mutex = Mutex.new
      @tcp_socket = nil

      if [:SOL_SOCKET, :SO_KEEPALIVE, :IPPROTO_TCP, :TCP_KEEPIDLE].all? { |c| Socket.const_defined? c }
        @keep_alive = options[:keep_alive]
      end
      if Socket.const_defined?(:TCP_KEEPIDLE)
        @keep_alive_idle = options[:keep_alive_idle]
      end
      if Socket.const_defined?(:TCP_KEEPCNT)
        @keep_alive_cnt = options[:keep_alive_cnt]
      end
      if Socket.const_defined?(:TCP_KEEPINTVL)
        @keep_alive_intvl = options[:keep_alive_intvl]
      end
      connect
    end

    def close
      @socket.close if @socket
      @tcp_socket.close if @tcp_socket
    end

    private

    def connect
      connect_retry_count = 0
      connect_retry_limit = 3
      connect_retry_interval = 1
      @mutex.synchronize do
        begin
          close

          @tcp_socket = TCPSocket.new(@remote_hostname, @remote_port)

          if @keep_alive
            @tcp_socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
            @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPIDLE, @keep_alive_idle) if @keep_alive_idle
            @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPCNT, @keep_alive_cnt) if @keep_alive_cnt
            @tcp_socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_KEEPINTVL, @keep_alive_intvl) if @keep_alive_intvl
          end
          if @tls
            require "openssl"
            context = OpenSSL::SSL::SSLContext.new(@ssl_method)
            context.ca_file = @ca_file if @ca_file
            context.verify_mode = @verify_mode if @verify_mode

            @socket = OpenSSL::SSL::SSLSocket.new(@tcp_socket, context)
            @socket.connect
            @socket.post_connection_check(@remote_hostname)
            # raise "verification error" if @socket.verify_result != OpenSSL::X509::V_OK
          else
            @socket = @tcp_socket
          end
        rescue
          if connect_retry_count < connect_retry_limit
            sleep connect_retry_interval
            connect_retry_count += 1
            retry
          else
            raise
          end
        end
      end
    end

    def send_msg(payload)
      if @timeout && @timeout >= 0
        method = :write_nonblock
      else
        method = :write
      end

      retry_limit = @retry_limit.to_i
      retry_interval = @retry_interval.to_f
      retry_count = 0

      payload << "\n"
      payload.force_encoding(Encoding::ASCII_8BIT)
      payload_size = payload.bytesize

      until payload_size <= 0
        start = get_time
        begin
          result = @mutex.synchronize { @socket.__send__(method, payload) }
          payload_size -= result
          payload.slice!(0, result) if payload_size > 0
        rescue IO::WaitReadable
          timeout_wait = @timeout - (get_time - start)
          retry if IO.select([@socket], nil, nil, timeout_wait)

          raise NonBlockingTimeout if @timeout_exception
          break
        rescue IO::WaitWritable
          timeout_wait = @timeout - (get_time - start)
          retry if IO.select(nil, [@socket], nil, timeout_wait)

          raise NonBlockingTimeout if @timeout_exception
          break
        rescue
          if retry_count < retry_limit
            sleep retry_interval
            retry_count += 1
            retry_interval *= 2 if @exponential_backoff
            connect
            retry
          else
            raise
          end
        end
      end
    end

    POSIX_CLOCK = if defined?(Process::CLOCK_MONOTONIC_COARSE)
        Process::CLOCK_MONOTONIC_COARSE
      elsif defined?(Process::CLOCK_MONOTONIC)
        Process::CLOCK_MONOTONIC
      elsif defined?(Process::CLOCK_REALTIME_COARSE)
        Process::CLOCK_REALTIME_COARSE
      elsif defined?(Process::CLOCK_REALTIME)
        Process::CLOCK_REALTIME
      end

    def get_time
      if POSIX_CLOCK
        Process.clock_gettime(POSIX_CLOCK)
      else
        Time.now.to_f
      end
    end
  end

  class UdpSender < Sender
    def initialize(remote_hostname, remote_port, options = {})
      super
      @socket = UDPSocket.new
    end

    private

    def send_msg(payload)
      @socket.send(payload, 0, @remote_hostname, @remote_port)
    end
  end
end
