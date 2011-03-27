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
    class NoReturnTo < StandardError; end
    MAX_REDIRECT_SIZE = 1024
    FIELDS = %w(
      assoc_handle assoc_type claimed_id contact delegate dh_consumer_public dh_gen
      dh_modulus error identity invalidate_handle mode ns op_endpoint openid
      realm reference response_nonce return_to server session_type sig
      signed trust_root)
    FIELD_SIGNED = %w(op_endpoint return_to response_nonce assoc_handle claimed_id identity)
    
    def initialize(env)
      @env = env
    end

    def params; @env['openid.provider.request.params'] ||= extract_open_id_params end
    def [](k); params[k] end
    def []=(k, v); params[k] = v end
      
    # Some accessor helpers
    FIELDS.each { |field|
      class_eval %{def #{field}; params['#{field}'] end}
    }
    def dh_modulus; params['dh_modulus'] && OpenID.ctwob(OpenID.base64_decode(params['dh_modulus'])) end
    def dh_gen; params['dh_gen'] && OpenID.ctwob(OpenID.base64_decode(params['dh_gen'])) end
    def dh_consumer_public; params['dh_consumer_public'] && OpenID.ctwob(OpenID.base64_decode(params['dh_consumer_public'])) end
    def session_type; OpenID::DH[params['session_type']] end
    def assoc_type; OpenID::Signatures[params['assoc_type']] end
      
    def return_positive(h = {}); return_response gen_pos(h) end
    def return_negative(h = {}); return_response gen_neg(h) end
    def return_error(error, h = {}); return_response gen_error(error, h) end
    
    def gen_html_fields(h)
      h.map {|k,v|
        "<input type='hidden' name='openid.#{k}' value='#{v}' />"
      }.join("\n")
    end
    
    private
    def nonces; @env['openid.provider.nonces'] end
    def handles; @env['openid.provider.handles'] end
    def private_handles; @env['openid.provider.private_handles'] end
    def options; @env['openid.provider.options'] end
    
    def extract_open_id_params
      openid_params = {}
      Request.new(@env).params.each { |k,v| openid_params[$'] = v if k =~ /^openid\./ }
      openid_params
    end
    
    def redirect_res(h)
      d = URI(return_to)
      d.query = d.query ? d.query + "&" + OpenID.url_encode(h) : OpenID.url_encode(h)
      [302, {'Location' => d.to_s, 'Content-Type' => "text/plain", 'Content-Length' => "0"}, [""]]
    end
    
    def return_response(h)
      raise NoReturnTo if return_to.nil?
      
      if OpenID.url_encode(h).size > MAX_REDIRECT_SIZE
        gen_htmlform(h)
      else
        redirect_res(h)
      end
    end

    def gen_htmlform(h)
      body = "<html><body onload='this.openid_form.submit();'>"
      body << "<form name='openid_form' method='post' action='#{return_to}'>"
      body << gen_html_fields(h)
      body << "<input type='submit' /></form></body></html>"
    end
    
    def gen_pos(h = {})
      assoc_handle = assoc_handle
      mac = handles[assoc_handle]
      if mac.nil? # Generate a mac and invalidate the association handle
        invalidate_handle = assoc_handle
        mac = OpenID::Signatures["HMAC-SHA256"].gen_mac
        private_handles[assoc_handle = OpenID.gen_handle] = mac
      end
      nonces[nonce = OpenID.gen_nonce] = assoc_handle
      
      r = h.merge(
        "ns" => OpenID::NS,
        "mode" => "id_res",
        "op_endpoint" => options['op_endpoint'] || Request.new(@env.merge("PATH_INFO" => "/", "QUERY_STRING" => "")).url,
        "return_to" => return_to,
        "response_nonce" => nonce,
        "assoc_handle" => assoc_handle
      )
      r["invalidate_handle"] = invalidate_handle if invalidate_handle

      r["signed"] = FIELD_SIGNED.select {|field| r[field] }.join(",")
      r["sig"] = OpenID.gen_sig(mac, r)
      r
    end

    def gen_neg(h = {})
      if mode == "checkid_immediate"
        h.merge "ns" => OpenID::NS, "mode" => "setup_needed"
      else
        h.merge "ns" => OpenID::NS, "mode" => "cancel"
      end
    end

    def gen_error(error, h = {})
      error_res = {"ns" => OpenID::NS, "mode" => "error", "error" => error}
      error_res["contact"] = options["contact"] if options["contact"]
      error_res["reference"] = options["reference"] if options["reference"]
      error_res.merge(h)
    end
  end

  # This is a Rack middleware:
  #   Rack::Builder.new {
  #     use Rack::OpenIDProvider, custom_options
  #     run MyProvider.new
  #   }
  class OpenIDProvider
    DEFAULT_OPTIONS = {
      'handle_timeout' => 36000,
      'private_handle_timeout' => 300,
      'nonce_timeout' => 300,
      'checkid_immediate' => false
    }

    def initialize(app, options = {})
      @app = app
      @options = DEFAULT_OPTIONS.merge(options)
      @handles, @private_handles, @nonces = {}, {}, {}
    end

    def call(env)
      req = Request.new(env)
      openid_req = OpenIDRequest.new(env)
      
      env['openid.provider.options'] = @options
      env['openid.provider.nonces'] = @nonces
      env['openid.provider.handles'] = @handles
      env['openid.provider.private_handles'] = @private_handles
      openid_req['mode'] = nil if not req.path_info == "/"
      clean_handles

      case openid_req.mode
      when 'associate'
        associate(env)
      when 'checkid_immediate'
        checkid_immediate(env)
      when 'checkid_setup'
        checkid_setup(env)
      when 'check_authentication'
        check_authentication(env)
      when nil
        default(env)
      else
        unknown_mode(env)
      end
    end

    private
    def clean_handles; end
    
    # OpenID handlers
    
    def associate(env)
      req = OpenIDRequest.new(env)
      p = req.dh_modulus
      g = req.dh_gen
      c = req.dh_consumer_public

      if req.session_type.nil? or req.assoc_type.nil?
        return direct_error("session type or association type not supported", "error_code" => "unsupported-type")
      elsif not req.session_type.compatible_key_size?(req.assoc_type.size)
        return direct_error("session type and association type are incompatible")
      end
      
      mac = req.assoc_type.gen_mac
      handle = OpenID.gen_handle
      r = {
        "assoc_handle" => handle,
        "session_type" => req['session_type'],
        "assoc_type" => req['assoc_type'],
        "expires_in" => @options['handle_timeout']
      }
      
      begin
        r.update req.session_type.to_hash(mac, p, g, c)

        @handles[handle] = mac
        direct_response r
      rescue OpenID::DH::SHA_ANY::MissingKey
        direct_error("dh_consumer_public missing")
      end
    end
    
    def checkid_immediate(env)
      if @options['checkid_immediate']
        @app.call(env)
      else
        OpenIDRequest.new(env).return_negative
      end
    end
    
    def checkid_setup(env); @app.call(env) end
    def default(env); @app.call(env) end
    def unknown_mode(env)
      req = OpenIDRequest.new(env)
      error = "Unknown mode"
      if req.return_to # Indirect Request
        req.return_error(error)
      else # Direct Request
        direct_error(error)
      end
    end

    def check_authentication(env)
      req = OpenIDRequest.new(env)
      assoc_handle = req.assoc_handle
      invalidate_handle = req.invalidate_handle
      nonce = req.response_nonce

      # Check if assoc_handle, nonce and signature are valid. Then delete the response nonce
      if mac = @private_handles[assoc_handle] and @nonces.delete(nonce) == assoc_handle and OpenID.gen_sig(mac, req.params) == req['sig']
        r = {"is_valid" => "true"}
        r["invalidate_handle"] = invalidate_handle if invalidate_handle && @handles[invalidate_handle].nil?
        direct_response r
      else
        direct_response "is_valid" => "false"
      end
    end
    
    def direct_response(h)
      body = OpenID.kv_encode(h.merge("ns" => OpenID::NS))
      [
        200,
        {"Content-Type" => "text/plain", "Content-Length" => body.size.to_s},
        [body]
      ]
    end

    def direct_error(error, h = {})
      error_res = {"mode" => "error", "error" => error}
      error_res["contact"] = @options["contact"] if @options["contact"]
      error_res["reference"] = @options["reference"] if @options["reference"]
      c,h,b = direct_response(error_res.merge(h))
      [400, h, b]
    end
  end
  
  class Yadis
    NOT_FOUND = "Not Found".freeze
    CONTENT =
%{<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
  <Service priority="0">
%s</Service>
</XRD>
</xrds:XRDS>
}.freeze

    def initialize(service)
      fragment = service.map { |k,v|
        v = [v] if not v.respond_to? :map
        v.map { |t| "    <#{k}>#{t}</#{k}>\n" }.join
      }.join
      @content = (CONTENT % [fragment]).freeze
    end
    
    def call(env)
      req = Request.new(env)
      if req.path_info != "/" and req.path != "/"
        [404, {"Content-Type" => "plain/text", "Content-Length" => NOT_FOUND.size.to_s}, [NOT_FOUND] ]
      end
      
      [200, {"Content-Type" => "application/xrds+xml", "Content-Length" => @content.size.to_s}, [@content] ]
    end
  end
end
