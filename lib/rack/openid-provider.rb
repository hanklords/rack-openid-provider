# Copyright (c) 2009 Mael Clerambault <maelclerambault@yahoo.fr>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


require 'rack'
require 'openssl'
require 'time'
require 'uri'

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
    def base64_encode(s); [s].pack("m0") end

    # Decode from base64
    def base64_decode(s); s.unpack("m0").first end

    # Generate _bytes_ random bytes
    def random_bytes(bytes); OpenSSL::Random.random_bytes(bytes) end

    # Generate a random string _length_ long
    def random_string(length); random_bytes(length / 2).unpack("H*")[0] end

    # Generate an OpenID signature
    def gen_sig(mac, params)
      signed = params["signed"].split(",").map {|k| [k, params[k]]}
      if mac.length == 20
        OpenID.base64_encode(Signatures["HMAC-SHA1"].sign(  mac, kv_encode(signed)))
      else
        OpenID.base64_encode(Signatures["HMAC-SHA256"].sign(mac, kv_encode(signed)))
      end
    end
    
    def gen_handle; Time.now.utc.iso8601 + OpenID.random_string(6) end
    def gen_nonce;  Time.now.utc.iso8601 + OpenID.random_string(6) end
  end

  module Signatures # :nodoc: all
    Associations = {}
    def self.[](k); Associations[k] end
    def self.[]=(k, v); Associations[k] = v end
      
    class Assoc
      def initialize(digest); @digest = digest end
      def sign(mac, value); OpenSSL::HMAC.digest(@digest.new, mac, value) end
      def size; @digest.new.size end
      def gen_mac; OpenID.random_bytes(size) end
    end

    Associations["HMAC-SHA1"] = Assoc.new(OpenSSL::Digest::SHA1)
    Associations["HMAC-SHA256"] = Assoc.new(OpenSSL::Digest::SHA256)
  end

  module DH # :nodoc: all
    DEFAULT_MODULUS=0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
    DEFAULT_GEN=2
    
    Sessions = {}
    def self.[](k); Sessions[k] end
    def self.[]=(k, v); Sessions[k] = v end    

    class SHA_ANY
      class MissingKey < StandardError; end

      def compatible_key_size?(size); @digest.new.size == size end
      def initialize(digest); @digest = digest end

      def to_hash(mac, p, g, consumer_public_key)
        raise MissingKey if consumer_public_key.nil?
        
        c = OpenSSL::BN.new(consumer_public_key.to_s)
        dh = gen_key(p || DEFAULT_MODULUS, g || DEFAULT_GEN)
        shared = OpenSSL::BN.new(dh.compute_key(c), 2)
        shared_hashed = @digest.digest(OpenID.btwoc(shared))
        {
          "dh_server_public" => OpenID.base64_encode(OpenID.btwoc(dh.pub_key)),
          "enc_mac_key" => OpenID.base64_encode(sxor(shared_hashed, mac))
        }
      end

      private
      def gen_key(p, g)
        dh = OpenSSL::PKey::DH.new
        dh.p = p
        dh.g = g
        dh.generate_key!
      end
      
      def sxor(s1, s2)
        s1.bytes.zip(s2.bytes).map { |x,y| x^y }.pack('C*')
      end
    end

    class NoEncryption
      def self.compatible_key_size?(size); true end
      def self.to_hash(mac, p, g, c); {"mac_key" => OpenID.base64_encode(mac)} end
    end
    
    Sessions["DH-SHA1"] = SHA_ANY.new(OpenSSL::Digest::SHA1)
    Sessions["DH-SHA256"] = SHA_ANY.new(OpenSSL::Digest::SHA256)
    Sessions["no-encryption"] = NoEncryption
  end
end


module Rack # :nodoc:
  class OpenIDRequest
    FIELDS = %w(
      assoc_handle assoc_type claimed_id contact delegate dh_consumer_public dh_gen
      dh_modulus error identity invalidate_handle mode ns op_endpoint
      realm reference response_nonce return_to server session_type sig
      signed trust_root).freeze
    MODES = %w(associate checkid_setup checkid_immediate check_authentication).freeze
    
    attr_reader :env
    def initialize(env) @env = env end

    def params; @env['openid.provider.request.params'] ||= extract_open_id_params end
    def [](k); params[k] end
    def []=(k, v); params[k] = v end
      
    # Some accessor helpers
    FIELDS.each { |field|
      class_eval %{def #{field}; params["#{field}"] end}
      class_eval %{def #{field}=(v); params["#{field}"] = v end}
    }
    MODES.each { |field|
      class_eval %{def #{field}?; valid? and mode == "#{field}" end}
    }
    
    def valid?; mode and Request.new(@env).path_info == "/" end
    def identifier_select?; OpenID::IDENTIFIER_SELECT == identity end
    def dh_modulus; params['dh_modulus'] && OpenID.ctwob(OpenID.base64_decode(params['dh_modulus'])) end
    def dh_gen; params['dh_gen'] && OpenID.ctwob(OpenID.base64_decode(params['dh_gen'])) end
    def dh_consumer_public; params['dh_consumer_public'] && OpenID.ctwob(OpenID.base64_decode(params['dh_consumer_public'])) end
    def session_type; OpenID::DH[params['session_type']] end
    def assoc_type; OpenID::Signatures[params['assoc_type']] end

    def nonces; @env['openid.provider.nonces'] end
    def handles; @env['openid.provider.handles'] end
    def private_handles; @env['openid.provider.private_handles'] end
    def options; @env['openid.provider.options'] end
    
    private
    def extract_open_id_params
      openid_params = {}
      Request.new(@env).params.each { |k,v| openid_params[$'] = v if k =~ /^openid\./ }
      openid_params
    end
  end
  
  class OpenIDResponse
    class NoReturnTo < StandardError
      def initialize(res)
        @res = res.error!("no return_to", "orig_mode" => @res["mode"])
      end
      def finish!; @res end
    end
    
    MODES = %w(error cancel setup_needed id_res is_valid)
    MAX_REDIRECT_SIZE = 1024
   
    def self.gen_html_fields(h)
      h.map {|k,v|
        "<input type='hidden' name='openid.#{k}' value='#{v}' />"
      }.join("\n")
    end
    
    OpenIDRequest::FIELDS.each { |field|
      class_eval %{def #{field}; params["#{field}"] end}
      class_eval %{def #{field}=(v); params["#{field}"] = v end}
    }
    MODES.each { |field|
      class_eval %{def #{field}?; mode == "#{field}" end}
    }
    
    def initialize(h = {})
      @h = h.merge("ns" => OpenID::NS)
      @direct = true
      @return_to = nil
    end
    
    def [](k) @h[k] end
    def []=(k,v) @h[k] = v end
    def params; @h end
      
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
#{OpenIDResponse.gen_html_fields(@h)}
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
  
  # This is a Rack middleware:
  #   Rack::Builder.new {
  #     use Rack::OpenIDProvider, custom_options
  #     run MyProvider.new
  #   }
  class OpenIDProvider
    FIELD_SIGNED = %w(op_endpoint return_to response_nonce assoc_handle claimed_id identity)
    
    class Error
      def initialize(app) @app = app end
      def call(env)
        c,h,b = @app.call(env)
        if OpenIDResponse === b and b.error?
          finish_error!(OpenIDRequest.new(env), b)
        else
          [c,h,b]
        end
      end
      
      def finish_error!(req, res)
        res["contact"]   = req.options["contact"]   if req.options["contact"]
        res["reference"] = req.options["reference"] if req.options["reference"]
        if !req.valid? or req.checkid_setup? or req.checkid_immediate?
          res.indirect!(req.return_to)
        end
        res.finish!
      rescue NoReturnTo => e
        e.finish!
      end
    end
    
    class Associate
      class NotSupported < StandardError; end
      class IncompatibleTypes < StandardError; end

      def initialize(app) @app = app end
      def call(env)
        c,h,b = @app.call(env)
        req = OpenIDRequest.new(env)
        if req.associate? and c == 404 and h["X-Cascade"] == "pass"
          associate(req)
        else
          [c,h,b]
        end
      end
      
      def associate(req)
        res = OpenIDResponse.new
        
        raise NotSupported if req.session_type.nil? or req.assoc_type.nil?
        raise IncompatibleTypes if !req.session_type.compatible_key_size?(req.assoc_type.size)

        mac = req.assoc_type.gen_mac
        handle = OpenID.gen_handle
        
        res["assoc_handle"] = handle
        res["session_type"] = req['session_type']
        res["assoc_type"] = req['assoc_type']
        res["expires_in"] = req.options['handle_timeout']
        
        res.params.merge! req.session_type.to_hash(mac, req.dh_modulus, req.dh_gen, req.dh_consumer_public)
        req.handles[handle] = mac
        res.finish!
      rescue IncompatibleTypes
        res.error!("session and association types are incompatible")
      rescue NotSupported
        res.error!("session type or association type not supported", "error_code" => "unsupported-type")
      rescue OpenID::DH::SHA_ANY::MissingKey
        res.error!("dh_consumer_public missing")
      end
    end
    
    class Checkid
      def initialize(app) @app = app end
      def call(env)
        c,h,b = @app.call(env)
        req = OpenIDRequest.new(env)
        
        if (req.checkid_setup? or req.checkid_immediate?) and c == 404 and h["X-Cascade"] == "pass"
          res = OpenIDResponse.new
          res.negative!
          finish_checkid! req, res
        elsif OpenIDResponse === b and (b.negative? or b.positive?)
          finish_checkid! req, b
        else
          [c,h,b]
        end
      end
      
      def finish_checkid!(req, res)
        if res.negative?
          res["mode"] = "setup_needed" if req.checkid_immediate?
        elsif res.positive?
          assoc_handle = req.assoc_handle
          mac = req.handles[assoc_handle]
          if mac.nil? # Generate a mac and invalidate the association handle
            invalidate_handle = assoc_handle
            mac = OpenID::Signatures["HMAC-SHA256"].gen_mac
            req.private_handles[assoc_handle = OpenID.gen_handle] = mac
          end
          req.nonces[nonce = OpenID.gen_nonce] = assoc_handle
          
          res["op_endpoint"] = req.options["op_endpoint"] || Request.new(req.env.merge("PATH_INFO" => "/", "QUERY_STRING" => "")).url
          res["return_to"] = req.return_to
          res["response_nonce"] = nonce
          res["assoc_handle"] = assoc_handle
          res["invalidate_handle"] = invalidate_handle if invalidate_handle
          res["signed"] = FIELD_SIGNED.select {|field| res[field] }.join(",")
          res["sig"] = OpenID.gen_sig(mac, res.params)
        end
        
        res.indirect!(req.return_to)
        res.finish!
      rescue NoReturnTo => e
        e.finish!
      end
    end
    
    class CheckAuthentication
      def initialize(app) @app = app end
      def call(env)
        c,h,b = @app.call(env)
        req = OpenIDRequest.new(env)
        if req.check_authentication?  and c == 404 and h["X-Cascade"] == "pass"
          check_authentication(req)
        else
          [c,h,b]
        end
      end

      def check_authentication(req)
        assoc_handle = req.assoc_handle
        invalidate_handle = req.invalidate_handle
        nonce = req.response_nonce

        # Check if assoc_handle, nonce and signature are valid. Then delete the response nonce
        if mac = req.private_handles[assoc_handle] and req.nonces.delete(nonce) == assoc_handle and OpenID.gen_sig(mac, req.params) == req['sig']
          res = OpenIDResponse.new("is_valid" => "true")
          res["invalidate_handle"] = invalidate_handle if invalidate_handle && req.handles[invalidate_handle].nil?
          res.finish!
        else
          OpenIDResponse.new("is_valid" => "false").finish!
        end
      end
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
        req = Request.new(env)
        oreq = OpenIDRequest.new(env)
        
        if !oreq.valid? and 
            (req.path_info == "/" or req.path == "/") and
            env['HTTP_ACCEPT'].include?(CONTENT_TYPE) and
            oreq.options['xrds']
          content = CONTENT % Request.new(env.merge("PATH_INFO" => "/", "QUERY_STRING" => "")).url
          [200, {"Content-Type" => CONTENT_TYPE, "Content-Length" => content.size.to_s}, [content] ]
        else
          @app.call(env)
        end
      end
    end

    DEFAULT_OPTIONS = {
      'handle_timeout' => 36000, 'private_handle_timeout' => 300, 'nonce_timeout' => 300,
      'handles' => {}, 'private_handles' => {}, 'nonces' => {},
      'middlewares' => [],
      'xrds' => true
    }
    DEFAULT_MIDDLEWARES = [Error, CheckAuthentication, Checkid, Associate, XRDS]

    attr_reader :options, :handles, :private_handles, :nonces
    def initialize(app, options = {})
      @options = DEFAULT_OPTIONS.merge(options)
      @middleware = (DEFAULT_MIDDLEWARES + @options['middlewares']).reverse.inject(app) {|a, m| m.new(a)}
      @handles, @private_handles, @nonces = @options['handles'], @options['private_handles'], @options['nonces']
    end

    def call(env)
      sev_env(env)
      clean_handles

      @middleware.call(env)
    end

    private
    def clean_handles; end
    def sev_env(env)
      env['openid.provider.options'] ||= @options
      env['openid.provider.nonces'] ||= @nonces
      env['openid.provider.handles'] ||= @handles
      env['openid.provider.private_handles'] ||= @private_handles      
    end
  end

end

require 'rack/openid-provider-sreg'
