mruby-fossa
=================================================
Fossa is a light-weight async network library.
-
This is a mruby binding.(Fossa has been bundled in.)
-

Usage:
--

```Ruby

manager = Fossa::Manager.new

hostname = Fossa.hostname
hosts = Fossa.resolve_all(hostname)
puts "#{hostname} : #{hosts}"

recv = manager.bind('udp://0.0.0.0:2018') do |connection, ev, data|
	puts "[#{connection}, #{ev}, #{data}]"
end

send = manager.connect('udp://255.255.255.255:2018') do |connection, ev, data|
	puts "[#{connection}, #{ev}, #{data}]"
	send.send "#{hosts[-1]}\0"
end
send.broadcast

http = manager.connect_http("http://www.baidu.com") do |connection, ev, data|
	case ev
	when Fossa::Connection::NS_POLL
	when Fossa::Connection::NS_CONNECT
		puts "Connect : ( #{data} )"
	when Fossa::Connection::NS_RECV
		puts "Received : ( #{data} )"
	when Fossa::Connection::NS_SEND
		puts "Sending request"
	when Fossa::Connection::NS_CLOSE
		puts 'Connection closed'
	else
		puts "[#{connection}, #{ev}, #{data.class}]"
	end
end

loop do
	manager.poll(0)
	sleep 1
end

```
