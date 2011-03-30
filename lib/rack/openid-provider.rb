require 'rack'
require 'openssl'
require 'time'
require 'uri'


module Rack
  module OpenID
    VERSION="0.0"

    NS="http://specs.openid.net/auth/2.0".freeze
    IDENTIFIER_SELECT="http://specs.openid.net/auth/2.0/identifier_select".freeze
    SERVER="http://specs.openid.net/auth/2.0/server".freeze
    SIGNON="http://specs.openid.net/auth/2.0/signon".freeze

    class << self
      # Implements OpenID btwoc function
      def btwoc(n)
        n = n.to_i
        raise if n < 0
        r = (n % 0x100).chr
        r = (n % 0x100).chr + r while (n /= 0x100) > 0
        r = 0.chr + r if r[0].ord >= 0x80
        r
      end
      
      # Inverse form of btwoc
      def ctwob(s)
        n, sl = 0, s.length - 1
        0.upto(sl) {|i|
          n += s[i].ord * 0x100 ** (sl - i)
        }
        n
      end

      # Encode OpenID parameters as a HTTP GET query string
      def url_encode(h); h.map { |k,v| "openid.#{Rack::Utils.escape(k)}=#{Rack::Utils.escape(v)}" }.join('&') end

      # Encode OpenID parameters as Key-Value format
      def kv_encode(h); h.map {|k,v| k.to_s + ":" + v.to_s + 10.chr }.join end

      # Decode OpenID parameters from Key-Value format
      def kv_decode(s); Hash[*s.split(10.chr).map {|l| l.split(":", 2) }.flatten] end

      # Encode in base64
      def base64_encode(s); [s.to_s].pack("m0") end

      # Decode from base64
      def base64_decode(s); s.to_s.unpack("m0").first end

      # Generate _bytes_ random bytes
      def random_bytes(bytes); OpenSSL::Random.random_bytes(bytes) end

      # Generate a random string _length_ long
      def random_string(length); random_bytes(length / 2).unpack("H*")[0] end

      # Generate an OpenID signature
      def gen_sig(mac, params)
        signed = params["signed"].split(",").map {|k| [k, params[k]]}
        base64_encode(Signatures.sign(mac, kv_encode(signed)))
      rescue Signatures::NotFound
        nil
      end
    end

    module Signatures # :nodoc: all
      class NotFound < StandardError; end

      @list = {}
      class << self
        attr_reader :list
        def [](k); @list[k] end
        def []=(k, v); @list[k] = v end

        def sign(mac, value)
          s = Signatures[mac.length]
          raise NotFound if s.nil?
          s.sign(mac, value)
        end
      end
        
      class Assoc
        def initialize(digest); @digest = digest end
        def sign(mac, value); OpenSSL::HMAC.digest(@digest.new, mac, value) end
        def size; @digest.new.size end
        def gen_mac; OpenID.random_bytes(size) end
      end

      @list["HMAC-SHA1"] = @list[20] = Assoc.new(OpenSSL::Digest::SHA1)
      @list["HMAC-SHA256"] = @list[32] = Assoc.new(OpenSSL::Digest::SHA256)
    end

    module Sessions # :nodoc: all
      DEFAULT_MODULUS=0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
      DEFAULT_GEN=2

      @list = {}
      class << self
        attr_reader :list
        def [](k); @list[k] end
        def []=(k, v); @list[k] = v end
      end

      class SHA_ANY
        class InvalidKey < StandardError; end
        class InvalidAssociation < StandardError; end

        def self.gen_key(p = DEFAULT_MODULUS, g = DEFAULT_GEN, priv_key = nil)
          dh = OpenSSL::PKey::DH.new
          dh.p = p
          dh.g = g
          dh.priv_key = priv_key
          dh.generate_key!
        end

        def initialize(key, digest); @key, @digest = key, digest end
        def pub_key; @key.pub_key end
        def crypted?; true end
        def enc_mac_key(mac, p, g, consumer_public_key)
          raise InvalidKey if consumer_public_key.nil?
          raise InvalidAssociation if mac.size != size
          
          c = consumer_public_key.to_bn
          shared = shared_hashed(p || DEFAULT_MODULUS, g || DEFAULT_GEN, c)
          sxor(shared, mac)
        end
        
        def mac(dh_server_public, enc_mac_key)
          s = dh_server_public.to_bn
          shared_hashed = shared_hashed(DEFAULT_MODULUS, DEFAULT_GEN, s)
          sxor(shared_hashed, enc_mac_key)
        end

        private
        def size; @digest.new.size end
        def shared_hashed(p, g, c)
          dh = (p == @key.p and g == @key.g) ? @key : SHA_ANY.gen_key(p, g, @key.priv_key)
          s = OpenSSL::BN.new(dh.compute_key(c), 2)
          @digest.digest(OpenID.btwoc(s))
        rescue OpenSSL::PKey::DHError
          raise InvalidKey
        end

        def sxor(s1, s2)
          s1.bytes.zip(s2.bytes).map { |x,y| x^y }.pack('C*')
        end
      end

      class NoEncryption
        def self.crypted?; false end
      end
      
      key = SHA_ANY.gen_key
      @list["DH-SHA1"] = SHA_ANY.new(key, OpenSSL::Digest::SHA1)
      @list["DH-SHA256"] = SHA_ANY.new(key, OpenSSL::Digest::SHA256)
      @list["no-encryption"] = NoEncryption
    end
    
    module Request
      FIELDS = %w(ns mode assoc_type session_type dh_modulus dh_gen dh_consumer_public
        claimed_id identity assoc_handle return_to realm
        op_endpoint response_nonce invalidate_handle signed sig).freeze
      MODES = %w(associate checkid_setup checkid_immediate check_authentication).freeze

      def [](k); params[k] end
      def []=(k, v); params[k] = v end

      FIELDS.each { |field|
        class_eval %{def #{field}; params["#{field}"] end}
        class_eval %{def #{field}=(v); params["#{field}"] = v end}
      }
      MODES.each { |field|
        class_eval %{def #{field}?; valid? and mode == "#{field}" end}
      }

      # Some accessor helpers
      def identifier_select?; OpenID::IDENTIFIER_SELECT == identity end
      def dh_modulus; params['dh_modulus'] && OpenID.ctwob(OpenID.base64_decode(params['dh_modulus'])) end
      def dh_gen; params['dh_gen'] && OpenID.ctwob(OpenID.base64_decode(params['dh_gen'])) end
      def dh_consumer_public; params['dh_consumer_public'] && OpenID.ctwob(OpenID.base64_decode(params['dh_consumer_public'])) end
      def session; OpenID::Sessions[session_type] end
      def assoc; OpenID::Signatures[assoc_type] end

      def realm_wildcard?; realm =~ %r(^https?://\.\*) end
      def realm_url; URI(realm.sub(".*", "")) rescue nil end
      def realm_match?(url)
        return true if realm.nil? or url.nil?

        realm = realm_url
        url = URI(url)
        !realm.fragment and
          realm.scheme == url.scheme and
          realm_wildcard? ? %r(\.?#{Regexp.escape(realm.host)}$) =~ url.host : realm.host == url.host and
          realm.port == url.port and
          %r(^#{Regexp.escape(realm.path)}) =~ url.path
      rescue URI::InvalidURIError
        false
      end
    end

    module Response
      FIELDS = %w(ns assoc_handle session_type assoc_type expires_in
        mac_key dh_server_public enc_mac_key error error_code mode
        op_endpoint claimed_id identity return_to response_nonce
        invalidate_handle signed sig is_valid).freeze
      MODES = %w(error cancel setup_needed id_res is_valid).freeze
      MAX_REDIRECT_SIZE = 1024
      
      def [](k) params[k] end
      def []=(k,v) params[k] = v end

      FIELDS.each { |field|
        class_eval %{def #{field}; params["#{field}"] end}
        class_eval %{def #{field}=(v); params["#{field}"] = v end}
      }
      MODES.each { |field|
        class_eval %{def #{field}?; mode == "#{field}" end}
      }

      def dh_server_public=(key) params["dh_server_public"] = OpenID.base64_encode(OpenID.btwoc(key)) end
      def dh_server_public; OpenID.ctwob(OpenID.base64_decode(params["dh_server_public"])) end
      def enc_mac_key=(mac) params["enc_mac_key"] = OpenID.base64_encode(mac) end
      def enc_mac_key; OpenID.base64_decode(params["enc_mac_key"]) end
      def mac_key=(mac) params["mac_key"] = OpenID.base64_encode(mac) end
      def mac_key; OpenID.base64_decode(params["mac_key"]) end
      def session; OpenID::Sessions[session_type] end
      def assoc; OpenID::Signatures[assoc_type] end
      def signed; (params["signed"] || '').split(",") end
      def signed=(list) params["signed"] = list.join(",") end
    end
  end

  # This is a Rack middleware:
  #   Rack::Builder.new {
  #     use Rack::OpenIDProvider, custom_options
  #     run MyProvider.new
  #   }
  class OpenIDProvider
    FIELD_SIGNED = %w(op_endpoint return_to response_nonce assoc_handle claimed_id identity)

    class Request
      include OpenID::Request

      attr_reader :env
      def initialize(env) @env = env end

      def valid?; mode and Rack::Request.new(@env).path_info == "/" end
      def params; @env['openid.provider.request.params'] ||= extract_open_id_params end
      def nonces; @env['openid.provider.nonces'] end
      def handles; @env['openid.provider.handles'] end
      def private_handles; @env['openid.provider.private_handles'] end
      def options; @env['openid.provider.options'] end

      private
      def extract_open_id_params
        openid_params = {}
        Rack::Request.new(@env).params.each { |k,v| openid_params[$'] = v if k =~ /^openid\./ }
        openid_params
      end
    end
    
    class Response
      include OpenID::Response
      
      class NoReturnTo < StandardError
        attr_reader :res
        def initialize(res)
          @res = res
          res.error!("no return_to", "orig_mode" => @res["mode"]) if not res.error?
        end
      end

      def self.gen_html_fields(h)
        h.map {|k,v|
          "<input type='hidden' name='openid.#{k}' value='#{v}' />"
        }.join("\n")
      end

      def params; @h end
      def initialize(h = {})
        @h = h.merge("ns" => OpenID::NS)
        @direct = true
        @return_to = nil
      end


      def direct?; @direct end
      def direct!; @direct = true end
        
      def indirect?; !direct? end
      def indirect!(return_to)
        raise NoReturnTo.new(self) if return_to.nil?
        @return_to = return_to
        @direct = false 
      end
      
      def html_form?; indirect? and OpenID.url_encode(@h).size > MAX_REDIRECT_SIZE end
      def redirect?; !html_form? end
      def negative?; cancel? or setup_needed? end
      def positive?; id_res? end

      def error!(error, h = {})
        @h.merge!(h)
        @h.merge! "mode" => "error", "error" => error
        finish!
      end
      
      def negative!(h = {})
        @h.merge!(h)
        @h["mode"] = "cancel"
        finish!
      end
          
      def positive!(h = {})
        @h.merge!(h)
        @h["mode"] = "id_res"
        finish!
      end
      
      def http_status
        if direct?
          error? ? 400 : 200
        else
          html_form? ? 200 : 302
        end
      end
      
      def http_headers
        headers = {"Content-Type" => "text/plain"}
        headers.merge!("Content-Length" => http_body.size.to_s)
        if direct?
          headers
        else
          if html_form?
            headers.merge!("Content-Type" => "text/html")
          else
            d = URI(@return_to)
            d.query = d.query ? d.query + "&" + OpenID.url_encode(@h) : OpenID.url_encode(@h)
            headers.merge!("Location" => d.to_s)
          end
        end
      end
      
      def http_body
        if direct?
          OpenID.kv_encode(@h)
        else
          if html_form?
            %(
  <html><body onload='this.openid_form.submit();'>
  <form name='openid_form' method='post' action='#{@return_to}'>"
  #{Response.gen_html_fields(@h)}
  <input type='submit' /></form></body></html>
            )
          else
            ""
          end
        end
      end

      def each; yield http_body end
      def finish!; [http_status, http_headers, self] end
      alias :to_a :finish!
    end

    class XRDS
      CONTENT_TYPE = "application/xrds+xml".freeze
      CONTENT =
  %{<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
  <Service priority="0">
    <Type>#{OpenID::SERVER}</Type>
    <URI>%s</URI>
  </Service>
</XRD>
</xrds:XRDS>}.freeze

      def initialize(app) @app = app end
      def call(env)
        if serve?(env)
          content = CONTENT % Request.new(env.merge("PATH_INFO" => "/", "QUERY_STRING" => "")).url
          [200, {"Content-Type" => CONTENT_TYPE, "Content-Length" => content.size.to_s}, [content] ]
        else
          @app.call(env)
        end
      end
      
      def serve?(env)
        req, oreq = Rack::Request.new(env), Request.new(env)
        !oreq.valid? and oreq.options['xrds'] and 
          (req.path_info == "/" or req.path == "/") and
          env['HTTP_ACCEPT'].include?(CONTENT_TYPE)
      end
    end
    
    class HandleRequests
      class NotSupported < StandardError; end
      class NoSecureChannel < StandardError; end

      def initialize(app) @app = app end
      def call(env)
        req = Request.new(env)
        
        # Before filters
        if (req.checkid_setup? or req.checkid_immediate?) and res = check_req(req)
          c,h,b = res.finish!
        else
          c,h,b = @app.call(env)
        end
        
        # After filters
        if req.valid? and c == 404 and h["X-Cascade"] == "pass"
          case req.mode
          when "associate"
            c,h,b = associate(req)
          when "checkid_setup", "checkid_immediate"
            res = Response.new
            res.negative!
            c,h,b = finish_checkid! req, res
          when "check_authentication"
            c,h,b = check_authentication(req)
          else
            c,h,b = Response.new.error!("Unknown mode")
          end
        elsif Response === b and (b.negative? or b.positive?)
          c,h,b = finish_checkid!(req, b)
        end
        
        # Finish filter
        if Response === b
          finish_error!(req, b) if b.error?
          b.indirect!(req.return_to) if indirect?(req, b)
          c,h,b = b.finish!
        end
        [c,h,b]
      rescue Response::NoReturnTo => e
        finish_error!(req, e.res)
      end

      private
      def check_req(req)
        res = Response.new
        if !req.return_to and !req.realm
          res.error!("The request has no return_to and no realm")
        elsif req.realm and !req.realm_url
          res.error!("Invalid realm")
        elsif !req.realm_match?(req.return_to)
          res.error!("return_to url does not match the realm")
        else
          false
        end
      end
      
      def associate(req)
        raise NotSupported if req.session.nil? or req.assoc.nil?
        raise NoSecureChannel if !req.session.crypted? and req.env["rack.url_scheme"] != "https"

        # Create an association handle
        mac = req.handles[handle = OpenIDProvider.gen_handle] = req.assoc.gen_mac
        
        res = Response.new
        res.assoc_handle = handle
        res.session_type = req.session_type
        res.assoc_type = req.assoc_type
        res.expires_in = req.options['handle_timeout']
        
        if req.session.crypted?
          res.dh_server_public = req.session.pub_key
          res.enc_mac_key = req.session.enc_mac_key(mac, req.dh_modulus, req.dh_gen, req.dh_consumer_public)
        else
          res.mac_key = mac
        end
        
        res.finish!
      rescue OpenID::Sessions::SHA_ANY::InvalidAssociation
        Response.new.error!("session and association types are incompatible")
      rescue NotSupported
        Response.new.error!("session type or association type not supported", "error_code" => "unsupported-type")
      rescue NoSecureChannel
        Response.new.error!("\"no-encryption\" session type requested without https connection")
      rescue OpenID::Sessions::SHA_ANY::InvalidKey
        Response.new.error!("bad or missing dh_consumer_public")
      end
      
      def finish_checkid!(req, res)
        if res.negative?
          res.mode = "setup_needed" if req.checkid_immediate?
        elsif res.positive? and !res.sig
          assoc_handle = req.assoc_handle
          mac = req.handles[assoc_handle]
          if mac.nil? or OpenIDProvider.handle_gracetime?(req, assoc_handle)
            # Handle is too old or unknown, create a private handle and invalidate this one
            invalidate_handle = assoc_handle
            mac = OpenID::Signatures["HMAC-SHA256"].gen_mac
            req.private_handles[assoc_handle = OpenIDProvider.gen_handle] = mac
          end
          req.nonces[nonce = OpenIDProvider.gen_nonce] = assoc_handle
          
          res.op_endpoint ||= req.options["op_endpoint"] || Rack::Request.new(req.env.merge("PATH_INFO" => "/", "QUERY_STRING" => "")).url
          res.return_to ||= req.return_to
          res.response_nonce ||= nonce
          res.assoc_handle ||= assoc_handle
          res.invalidate_handle ||= invalidate_handle if invalidate_handle
          res.signed = FIELD_SIGNED.select {|field| res[field] }
          res.sig = OpenID.gen_sig(mac, res.params)
        end
        
        res.finish!
      end

      def check_authentication(req)
        assoc_handle = req.assoc_handle
        invalidate_handle = req.invalidate_handle
        nonce = req.response_nonce

        # Check if assoc_handle, nonce and signature are valid. Then delete the response nonce
        if mac = req.private_handles[assoc_handle] and req.nonces.delete(nonce) == assoc_handle and OpenID.gen_sig(mac, req.params) == req['sig']
          res = Response.new("is_valid" => "true")
          res.invalidate_handle = invalidate_handle if invalidate_handle && req.handles[invalidate_handle].nil?
          res.finish!
        else
          Response.new("is_valid" => "false").finish!
        end
      end
            
      def finish_error!(req, res)
        res.contact   = req.options["contact"]   if req.options["contact"]
        res.reference = req.options["reference"] if req.options["reference"]
        res.finish!
      end
      
      def indirect?(req, res)
        res.negative? or res.positive? or
          req.checkid_setup? or req.checkid_immediate? or
          ((!req.valid? or req.env['HTTP_REFERER']) and req.return_to)
      end
    end

    DEFAULT_OPTIONS = {
      'handle_timeout' => 36000, 'private_handle_timeout' => 300, 'nonce_timeout' => 300,
      'handles' => {}, 'private_handles' => {}, 'nonces' => {},
      'xrds' => true
    }
    DEFAULT_MIDDLEWARES = [XRDS, HandleRequests]

    attr_reader :options, :handles, :private_handles, :nonces
    def initialize(app, options = {})
      @options = DEFAULT_OPTIONS.merge(options)
      @middleware = DEFAULT_MIDDLEWARES.reverse.inject(app) {|a, m| m.new(a)}
      @handles = @options.delete('handles')
      @private_handles = @options.delete('private_handles')
      @nonces = @options.delete('nonces')
    end

    def call(env)
      sev_env(env)
      clean_handles

      @middleware.call(env)
    end

    private
    def clean_handles
      @nonces.delete_if { |k,v|
        OpenIDProvider.handle_lifetime(k) >= @options['nonce_timeout']
      }
      @private_handles.delete_if { |k,v|
        OpenIDProvider.handle_lifetime(k) >= @options['private_handle_timeout']
      }
      @handles.delete_if { |k,v|
        OpenIDProvider.handle_lifetime(k) >= @options['handle_timeout'] + @options['private_handle_timeout']
      }
    end
    
    def sev_env(env)
      env['openid.provider.options'] ||= @options
      env['openid.provider.nonces'] ||= @nonces
      env['openid.provider.handles'] ||= @handles
      env['openid.provider.private_handles'] ||= @private_handles      
    end

    class << self
      def gen_handle; Time.now.utc.iso8601 + OpenID.random_string(6) end
      alias :gen_nonce :gen_handle
      
      def handle_gracetime?(req, h)
        handle_lifetime(h) > req.options['handle_timeout']
      end
      
      def handle_lifetime(h)
        Time.now.utc - (Time.iso8601(h[/^[0-9TZ:-]*Z/]) rescue Time.utc(0))
      end
    end
  end
      
end

require 'rack/openid-provider-sreg'
