require "xspear/version"
require "xspear/banner"
require "xspear/log"
require "xspear/xspearRepoter"
require 'net/http'
require 'uri'
require 'optparse'
require 'colorize'
require "selenium-webdriver"
require "progress_bar"

module xspear
  class Error < StandardError; end
end

class xspearScan
  def initialize(url, options)
    @url = url
    @data = options['data']
    @headers = options['headers']
    if options['params'].nil?
      @params = options['params']
    else
      @params = options['params'].split(",")
    end
    if options['cp'].nil?
      @custom_payload = nil
    else
      @custom_payload = File.open(options['cp'])
    end
    if options['all'] == true
      @all = true
    else
      @all = false
    end
    if options['nx'] == true
      @nx = true
    else
      @nx = false
    end
    @thread = options['thread']
    @output = options['output']
    @verbose = options['verbose']
    @blind_url = options['blind']
    @report = xspearRepoter.new @url, Time.now, (@data.nil? ? "GET" : "POST")
    @filtered_objects = {}
    @reflected_params = []
    @param_check_switch = 0
    @progress_bar = nil
  end

  class ScanCallbackFunc
    def initialize(url, method, query, response, report)
      @url = url
      @method = method
      @query = query
      @response = response
      @report = report
      # self.run
    end

    def run
      # Override callback function..

      # return type: Array(state, message)
      # + state: i(INFO), v(VULN), s(SYSTEM)
      # + message: your message

      # e.g
      # return "v", "reflected xss with #{query}"
    end
  end

  class CallbackStringMatch < ScanCallbackFunc
    def run
      if @response.body.include? @query
        [true, "reflected #{@query}"]
      else
        [false, "not reflected #{@query}"]
      end
    end
  end

  class CallbackNotAdded < ScanCallbackFunc
    def run
      if @response.body.include? @query
        if (@verbose.to_i > 1)
          time = Time.now
          puts '[I]'.blue + " [#{time.strftime('%H:%M:%S')}] [#{@response.code}/#{@response.message}] reflected #{@query}"
        end
        [false, true]
      else
        [false, "Not reflected #{@query}"]
      end
    end
  end

  class CallbackCheckWAF < ScanCallbackFunc
    def run
      pattern = {}
      pattern['AWS'] = 'AWS Web Application FW'
      pattern['ACE XML Gateway'] = 'Cisco ACE XML Gateway'
      pattern['cloudflare'] = 'CloudFlare'
      pattern['cf-ray'] = 'CloudFlare'
      pattern['Error from cloudfront'] = 'Amazone CloudFront'
      pattern['Protected by COMODO WAF'] = 'Comodo Web Application FW'
      pattern['X-Backside-Transport.*?(OK|FAIL)'] = 'IBM WebSphere DataPower'
      pattern['FORTIWAFSID'] = 'FortiWeb Web Application FW'
      pattern['ODSESSION'] = 'Hyperguard Web Application FW'
      pattern['AkamaiGHost'] = 'KONA(AKAMAIGHOST)'
      pattern['Mod_Security|NOYB'] = 'ModSecurity'
      pattern['naxsi/waf'] = 'NAXSI'
      pattern['NCI__SessionId='] = 'NetContinuum Web Application FW'
      pattern['citrix_ns_id'] = 'Citrix NetScaler'
      pattern['NSC_'] = 'Citrix NetScaler'
      pattern['NS-CACHE'] = 'Citrix NetScaler'
      pattern['newdefend'] = 'Newdefend Web Application FW'
      pattern['NSFocus'] = 'NSFOCUS Web Application FW'
      pattern['PLBSID'] = 'Profense Web Application Firewall'
      pattern['X-SL-CompState'] = 'AppWall (Radware)'
      pattern['safedog'] = 'Safedog Web Application FW'
      pattern['Sucuri/Cloudproxy|X-Sucuri'] = 'CloudProxy WebSite FW'
      pattern['X-Sucuri'] = 'CloudProxy WebSite FW'
      pattern['st8(id)'] = 'Teros/Citrix Application FW'
      pattern['st8(_wat)'] = 'Teros/Citrix Application FW'
      pattern['st8(_wlf)'] = 'Teros/Citrix Application FW'
      pattern['F5-TrafficShield'] = 'TrafficShield'
      pattern['Rejected-By-UrlScan'] = 'MS UrlScan'
      pattern['Secure Entry Server'] = 'USP Secure Entry Server'
      pattern['nginx-wallarm'] = 'Wallarm Web Application FW'
      pattern['WatchGuard'] = 'WatchGuard '
      pattern['X-Powered-By-360wzb'] = '360 Web Application'
      pattern['WebKnight'] = 'WebKnight Application FW'

      pattern.each do |key,value|
        if !@response[key].nil?
          time = Time.now
          puts '[I]'.blue + " [#{time.strftime('%H:%M:%S')}] Found WAF: #{value}"
          @report.add_issue("i","d","-","-","<original query>","Found WAF: #{value}")
        end
      end

      [false, "not reflected #{@query}"]
    end
  end


  class CallbackCheckHeaders < ScanCallbackFunc
    def run
      if !@response['Server'].nil?
        # Server header
        @report.add_issue("i","s","-","-","<original query>","Found Server: #{@response['Server']}")
      end

      if @response['Strict-Transport-Security'].nil?
        # HSTS
        @report.add_issue("i","s","-","-","<original query>","Not set HSTS")
      end


      if !@response['Content-Type'].nil?
        @report.add_issue("i","s","-","-","<original query>","Content-Type: #{@response['Content-Type']}")
      end


      if !@response['X-XSS-Protection'].nil?
        @report.add_issue("i","s","-","-","<original query>","Not set X-XSS-Protection")
      end


      if !@response['X-Frame-Options'].nil?
        @report.add_issue("i","s","-","-","<original query>","X-Frame-Options: #{@response['X-Frame-Options']}")
      else
        @report.add_issue("l","s","-","-","<original query>","Not Set X-Frame-Options")
      end


      if !@response['Content-Security-Policy'].nil?
        begin
          csp = @response['Content-Security-Policy']
          csp = csp.split(';')
          r = " "
          csp.each do |c|
            d = c.split " "
            r = r+d[0]+" "
          end
          @report.add_issue("i","s","-","-","<original query>","Enabled CSP")
        rescue
          @report.add_issue("i","s","-","-","<original query>","CSP ERROR")
        end
      else
        @report.add_issue("m","s","-","-","<original query>","Not Set CSP")
      end

      [false, "not reflected #{@query}"]
    end
  end

  class CallbackErrorPatternMatch < ScanCallbackFunc
    def run
      info = "Found"
      if @response.body.to_s.match(/(SQL syntax.*MySQL|Warning.*mysql_.*|MySqlException \(0x|valid MySQL result|check the manual that corresponds to your (MySQL|MariaDB) server version|MySqlClient\.|com\.mysql\.jdbc\.exceptions)/i)
        info = info + "MYSQL Error"
      end
      if @response.body.to_s.match(/(Driver.* SQL[\-\_\ ]*Server|OLE DB.* SQL Server|\bSQL Server.*Driver|Warning.*mssql_.*|\bSQL Server.*[0-9a-fA-F]{8}|[\s\S]Exception.*\WSystem\.Data\.SqlClient\.|[\s\S]Exception.*\WRoadhouse\.Cms\.|Microsoft SQL Native Client.*[0-9a-fA-F]{8})/i)
        info = info + "MSSQL Error"
      end
      if @response.body.to_s.match(/(\bORA-\d{5}|Oracle error|Oracle.*Driver|Warning.*\Woci_.*|Warning.*\Wora_.*)/i)
        info = info + "Oracle Error"
      end
      if @response.body.to_s.match(/(PostgreSQL.*ERROR|Warning.*\Wpg_.*|valid PostgreSQL result|Npgsql\.|PG::SyntaxError:|org\.postgresql\.util\.PSQLException|ERROR:\s\ssyntax error at or near)/i)
        info = info + "Postgres Error"
      end
      if @response.body.to_s.match(/(Microsoft Access (\d+ )?Driver|JET Database Engine|Access Database Engine|ODBC Microsoft Access)/i)
        info = info + "MSAccess Error"
      end
      if @response.body.to_s.match(/(SQLite\/JDBCDriver|SQLite.Exception|System.Data.SQLite.SQLiteException|Warning.*sqlite_.*|Warning.*SQLite3::|\[SQLITE_ERROR\])/i)
        info = info + "SQLite Error"
      end
      if @response.body.to_s.match(/(Warning.*sybase.*|Sybase message|Sybase.*Server message.*|SybSQLException|com\.sybase\.jdbc)/i)
        info = info + "SyBase Error"
      end
      if @response.body.to_s.match(/(Warning.*ingres_|Ingres SQLSTATE|Ingres\W.*Driver)/i)
        info = info + "Ingress Error"
      end

      if info.length > 5
        [true, "#{@info}"]
      else
        [false, "#{@info}"]
      end
    end
  end

  class CallbackXSSSelenium < ScanCallbackFunc
    def run
      begin
      options = Selenium::WebDriver::Firefox::Options.new(args: ['-headless'])
      driver = Selenium::WebDriver.for(:firefox, options: options)
      if @method == "GET"
        begin
          driver.get(@url+"?"+@query)
          alert = driver.switch_to().alert()
          if alert.text.to_s == "45"
            driver.quit
            return [true, "found alert/prompt/confirm (45) in selenium!! #{@query}"]
          else
            driver.quit
            return [true, "found alert/prompt/confirm event in selenium #{@query}"]
          end
        rescue Selenium::WebDriver::Error::UnexpectedAlertOpenError => e
          driver.quit
          return [true, "found alert/prompt/confirm error base in selenium #{@query}"]
        rescue => e
          driver.quit
          return [false, "not found alert/prompt/confirm event #{@query}"]
        end
      end
    rescue => e
      log('s', "Error Selenium : #{e}")
    end
    end
  end

  def run
    r = []
    event_handler = [
        'onabort',
        'onactivate',
        'onafterprint',
        'onafterscriptexecute',
        'onafterupdate',
        'onanimationcancel',
        'onanimationstart',
        'onauxclick',
        'onbeforeactivate',
        'onbeforecopy',
        'onbeforecut',
        'onbeforedeactivate',
        'onbeforeeditfocus',
        'onbeforepaste',
        'onbeforeprint',
        'onbeforescriptexecute',
        'onbeforeunload',
        'onbeforeupdate',
        'onbegin',
        'onblur',
        'onbounce',
        'oncanplay',
        'oncanplaythrough',
        'oncellchange',
        'onchange',
        'onclick',
        'oncontextmenu',
        'oncontrolselect',
        'oncopy',
        'oncut',
        'ondataavailable',
        'ondatasetchanged',
        'ondatasetcomplete',
        'ondblclick',
        'ondeactivate',
        'ondrag',
        'ondragdrop',
        'ondragend',
        'ondragenter',
        'ondragleave',
        'ondragover',
        'ondragstart',
        'ondrop',
        'onend',
        'onerror',
        'onerrorupdate',
        'onfilterchange',
        'onfinish',
        'onfocus',
        'onfocusin',
        'onfocusout',
        'onhashchange',
        'onhelp',
        'oninput',
        'oninvalid',
        'onkeydown',
        'onkeypress',
        'onkeyup',
        'onlayoutcomplete',
        'onload',
        'onloadend',
        'onloadstart',
        'onloadstart',
        'onlosecapture',
        'onmediacomplete',
        'onmediaerror',
        'onmessage',
        'onmousedown',
        'onmouseenter',
        'onmouseleave',
        'onmousemove',
        'onmouseout',
        'onmouseover',
        'onmouseup',
        'onmousewheel',
        'onmove',
        'onmoveend',
        'onmovestart',
        'onoffline',
        'ononline',
        'onoutofsync',
        'onpageshow',
        'onpaste',
        'onpause',
        'onplay',
        'onplaying',
        'onpointerdown',
        'onpointerenter',
        'onpointerleave',
        'onpointermove',
        'onpointerout',
        'onpointerover',
        'onpointerup',
        'onpopstate',
        'onprogress',
        'onpropertychange',
        'onreadystatechange',
        'onredo',
        'onrepeat',
        'onreset',
        'onresize',
        'onresizeend',
        'onresizestart',
        'onresume',
        'onreverse',
        'onrowdelete',
        'onrowexit',
        'onrowinserted',
        'onrowsenter',
        'onscroll',
        'onsearch',
        'onseek',
        'onselect',
        'onselectionchange',
        'onselectstart',
        'onstart',
        'onstop',
        'onstorage',
        'onsubmit',
        'onsyncrestored',
        'ontimeerror',
        'ontimeupdate',
        'ontoggle',
        'ontouchend',
        'ontouchmove',
        'ontouchstart',
        'ontrackchange',
        'ontransitioncancel',
        'ontransitionend',
        'ontransitionrun',
        'onundo',
        'onunhandledrejection',
        'onunload',
        'onurlflip',
        'onvolumechange',
        'onwaiting',
        'onwheel',
        'whatthe=""onload',
        'onpointerrawupdate'
    ]
    tags = [
        "script",
        "iframe",
        "sv