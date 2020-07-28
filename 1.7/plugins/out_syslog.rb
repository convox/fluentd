module Fluent
  module Plugin
    class SyslogOutput < Fluent::BufferedOutput
      Fluent::Plugin.register_output("syslog", self)

      config_param :host, :string, :default => ""
      config_param :port, :integer, :default => 514

      config_param :facility, :string, :default => "user"
      config_param :severity, :string, :default => "debug"

      config_param :hostname_key, :string, :default => nil
      config_param :payload_key, :string, :default => "message"
      config_param :tag_key, :string, :default => nil

      def initialize
        super
        require "socket"
        require "syslog_protocol"
        require "timeout"
      end

      def configure(conf)
        super
        raise Fluent::ConfigError.new("host required") if not conf["host"]

        @host = conf["host"]
        @port = conf["port"]

        @facilty = conf["facility"]
        @severity = conf["severity"]
        @hostname_key = conf["hostname_key"]
        @payload_key = conf["payload_key"]
        @tag_key = conf["tag_key"]
      end

      def format(tag, time, record)
        [tag, time, record].to_msgpack
      end

      def create_tcp_socket(host, port)
        begin
          Timeout.timeout(10) do
            begin
              socket = TCPSocket.new(host, port)
            rescue Errno::ENETUNREACH
              retry
            end
          end
          socket = TCPSocket.new(host, port)
          secs = Integer(1)
          usecs = Integer((1 - secs) * 1_000_000)
          optval = [secs, usecs].pack("l_2")
          socket.setsockopt Socket::SOL_SOCKET, Socket::SO_SNDTIMEO, optval
        rescue SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EPIPE, Timeout::Error, OpenSSL::SSL::SSLError, Timeout::Error => e
          log.warn "out:syslog: failed to open tcp socket  #{@host}:#{@port} :#{e}"
          socket = nil
        end
        socket
      end

      # This method is called when starting.
      def start
        super
      end

      # This method is called when shutting down.
      def shutdown
        super
      end

      def write(chunk)
        chunk.msgpack_each { |(tag, time, record)|
          send_to_syslog(tag, time, record)
        }
      end

      def send_to_syslog(tag, time, record)
        packet = SyslogProtocol::Packet.new

        packet.facility = @facility
        packet.severity = @severity
        packet.hostname = record[@hostname_key] || hostname
        packet.time = record["time"] ? Time.parse(record["time"]) : Time.at(time)
        packet.tag = (@tag_key ? record[@tag_key] : tag)[0..31]
        packet.content = record[@payload_key]

        p [:packet, packet]

        begin
          @socket ||= create_tcp_socket(@host, @port)
          @socket.write packet.assemble(4096) + "\n"
          @socket.flush
        rescue SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET, Errno::EPIPE, Timeout::Error, OpenSSL::SSL::SSLError => e
          log.warn "out:syslog: connection error by #{@host}:#{@port} :#{e}"
          @socket = nil
          raise #{e}
        end
      end
    end

    # class Time
    #   def timezone(timezone = "UTC")
    #     old = ENV["TZ"]
    #     utc = self.dup.utc
    #     ENV["TZ"] = timezone
    #     output = utc.localtime
    #     ENV["TZ"] = old
    #     output
    #   end
    # end
  end
end
