# Sample HTTPS service used to verify that a previously unseen application is
# traced without configuration. Contains no instrumentation.
#
# Written against the standard library only, so that running it requires no
# package installation and nothing is added to the process that could be
# mistaken for instrumentation.

require 'socket'
require 'openssl'
require 'json'

USERS = [
  { id: 1, name: 'ada' },
  { id: 2, name: 'grace' },
  { id: 3, name: 'katherine' }
].freeze

def route(method, path)
  case [method, path]
  when %w[GET /health]        then [200, 'OK', 'ok', 'text/plain']
  when %w[GET /users]         then [200, 'OK', JSON.generate(USERS), 'application/json']
  when %w[POST /users]        then [201, 'Created', JSON.generate(id: USERS.length + 1, name: 'new'), 'application/json']
  when %w[GET /users/999]     then [404, 'Not Found', JSON.generate(error: 'no such user'), 'application/json']
  when %w[GET /slow]          then sleep(0.15) && [200, 'OK', 'slow', 'text/plain']
  when %w[GET /error]         then [500, 'Internal Server Error', JSON.generate(error: 'deliberate failure'), 'application/json']
  else
    return [200, 'OK', JSON.generate(USERS.first), 'application/json'] if path.start_with?('/users/')

    [404, 'Not Found', JSON.generate(error: 'no such route'), 'application/json']
  end
end

def handle(conn)
  request_line = conn.gets
  return if request_line.nil?

  method, path, = request_line.split(' ')

  # Consume the headers so the request is fully read before responding.
  content_length = 0
  while (line = conn.gets)
    break if line.strip.empty?

    content_length = line.split(':', 2)[1].to_i if line =~ /\Acontent-length:/i
  end
  conn.read(content_length) if content_length.positive?

  status, reason, body, type = route(method, path)
  conn.write(
    "HTTP/1.1 #{status} #{reason}\r\n" \
    "Content-Type: #{type}\r\n" \
    "Content-Length: #{body.bytesize}\r\n" \
    "Connection: close\r\n" \
    "\r\n#{body}"
  )
rescue StandardError
  # A client that disconnects mid-request is routine and not worth reporting.
  nil
ensure
  begin
    conn.close
  rescue StandardError
    nil
  end
end

port = Integer(ENV.fetch('PORT', '8446'))
cert = ENV.fetch('CERT', '../certs/cert.pem')
key  = ENV.fetch('KEY', '../certs/key.pem')

context = OpenSSL::SSL::SSLContext.new
context.cert = OpenSSL::X509::Certificate.new(File.read(cert))
context.key  = OpenSSL::PKey::RSA.new(File.read(key))

server = OpenSSL::SSL::SSLServer.new(TCPServer.new('0.0.0.0', port), context)
puts "ruby-api listening on #{port}"

loop do
  conn = begin
    server.accept
  rescue OpenSSL::SSL::SSLError, Errno::ECONNRESET
    next
  end
  Thread.new { handle(conn) }
end
