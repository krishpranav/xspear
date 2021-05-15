#!/usr/bin/env ruby
require "xspear"

xoptions = Struct.new(:url, :data, :headers, :params, :options)

def true?(obj)
  obj.to_s.downcase == "true"
end

class Parser
  def self.parse(options)
    args = XOptions.new('xspear')
    args.options = {}
    if options.empty?
      banner
      puts 'please ' + "'-h'".yellow + ' option'
      exit
    end
    opt_parser = OptionParser.new do |opts|
      opts.banner = "Usage: xspear -u [target] -[options] [value]\n[ e.g ]\n$ xspear -u 'https://www.hahwul.com/?q=123' --cookie='role=admin' -v 1 -a \n$ xspear -u 'http://testphp.vulnweb.com/listproducts.php?cat=123' -v 2\n$ xspear -u 'http://testphp.vulnweb.com/listproducts.php?cat=123' -v 0 -o json\n\n[ Options ]"


      opts.on('-u', '--url=target_URL', '[required] Target Url') do |n|
        args.url = n
      end


      opts.on('-d', '--data=POST Body', '[optional] POST Method Body data') do |n|
        args.options['data'] = n
      end

      opts.on('-a','--test-all-params', '[optional] test to all params(include not reflected)') do
        args.options['all'] = true
      end

      opts.on('--no-xss', '[optional] no testing xss, only parameters analysis') do
        args.options['nx'] = true
      end

      opts.on('--headers=HEADERS', '[optional] Add HTTP Headers') do |n|
        args.options['headers'] = n
      end


      opts.on('--cookie=COOKIE', '[optional] Add Cookie') do |n|
        args.options['cookie'] = 'Cookie: ' + n
      end

      opts.on('--custom-payload=FILENAME', '[optional] Load custom payload json file') do |n|
        args.options['cp'] = n
      end

      opts.on('--raw=FILENAME', '[optional] Load raw file(e.g raw_sample.txt)') do |n|
        args.options['raw'] = n
      end

      opts.on('--raw-ssl=BOOLEAN', '[optional] http/https switch for burp raw file e.g: true/false') do |n|
        args.options['raw-ssl'] = n
      end

      opts.on('-p', '--param=PARAM', '[optional] Test paramters') do |n|
        args.options['params'] = n
      end

      opts.on('-b', '--BLIND=URL', '[optional] Add vector of Blind XSS',' + with XSS Hunter, ezXSS, HBXSS, etc...',' + e.g : -b https://hahwul.xss.ht') do |n|
        args.options['blind'] = n
      end


      opts.on('-t', '--threads=NUMBER', '[optional] thread , default: 10') do |n|
        args.options['thread'] = n
      end


      opts.on('-o', '--output=FORMAT', '[optional] Output format (cli , json, html)') do |n|
        args.options['output'] = n
      end

      opts.on('-c', '--config=FILENAME', '[optional] Using config.json') do |n|
        args.options['config'] = n
      end

      opts.on('-v', '--verbose=0~3', '[optional] Show log depth',
              ' + v=0 : quite mode(only result)',
              ' + v=1 : show scanning status(default)',
              ' + v=2 : show scanning logs',
              ' + v=3 : show detail log(req/res)') do |n|
        args.options['verbose'] = n
      end


      opts.on('-h', '--help', 'Prints this help') do
        banner
        puts opts
        exit
      end
      opts.on('--version', 'Show XSpear version') do
        puts XSpear::VERSION
        exit
      end
      opts.on('--update', 'Show how to update') do
        puts "[RubyGem user]               : $ gem update XSpear"
        puts "[Soft | Developer & Git clone user] : $ git pull -v "
        puts "[Hard | Developer & Git clone user] : $ git reset --hard HEAD; git pull -v "
        exit
      end
    end
    opt_parser.parse!(options)
    args
  end
end
options = Parser.parse ARGV

if !options.options['raw'].nil?
  begin
    method = ""
    path = ""
    headers_hash = {}
    headers = ""
    data = ""
    switch = true
    file = File.open options.options['raw']
    r = file.read
    file.close
    r.each_line do |line|
      if switch
        temp = line.split(" ")
        method = temp[0]
        path = temp[1]
        switch = false
      else
        if line.include? ": "
          temp = line.split(": ")
          hn = temp[0]
          hd = line.sub(hn+": ", "")
          headers_hash[hn] = hd
          headers = headers + "#{hn}: #{hd}\n"
        elsif line.size > 2
          # data
          data = line
        else
          # blank
        end
      end
    end
    # Burp or ZAP
    # http, https로 시작하면 zap 아니면 burp 포맷
    url = ""
    if (path.index('http://') == 0 || path.index('https://') == 0)
      url = path
    else
      if options.options['raw-ssl'].nil?
        url = "https://"+headers_hash['Host'].to_s.chomp!+"/"+path
      else
        if true? options.options['raw-ssl']
          url = "https://"+headers_hash['Host'].to_s.chomp!+"/"+path
        else
          url = "http://"+headers_hash['Host'].to_s.chomp!+"/"+path
        end
      end
    end
    puts url
    options.url = url
    if headers.length > 0
      options.options['headers'] = headers
    end
    if method == "POST" && data.size
      options.options['data'] = data
    end
  rescue => e
    puts "RAW file Error #{e}"
    exit
  end
end

exit unless options.url
options.options['thread'] = 10 unless options.options['thread']
options.options['verbose'] = 1 unless options.options['verbose']
options.options['thread'] = options.options['thread'].to_i

if !options.options['config'].nil?
  f = File.open(options.options['config'])
  buf = f.read
  cjson = JSON.parse buf
  cjson.each do |key,value|
    if value.to_s.size > 0
      options.options[key] = value
    end
  end
end

if options.options['verbose'].to_i != 0
  banner
end
s = XspearScan.new options.url, options.options
s.run
