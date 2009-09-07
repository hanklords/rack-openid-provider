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

  class << self
    # Implements \OpenID btwoc function
    def btwoc(n)
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

    # Encode \OpenID parameters as a HTTP GET query string
    def url_encode(h); h.map { |k,v| "openid.#{Rack::Utils.escape(k)}=#{Rack::Utils.escape(v)}" }.join('&') end

    # Encode \OpenID parameters as Key-Value format
    def kv_encode(h); h.map {|k,v| "openid." + k.to_s + ":" + v.to_s + 10.chr }.join end

    # Decode \OpenID parameters from Key-Value format
    def kv_decode(s); Hash[*s.split(10.chr).map {|l| l.split(":", 2) }.flatten] end

    # Encode in base64
    def base64_encode(s); [s].pack("m").delete("\n") end

    # Decode from base64
    def base64_decode(s); s.unpack("m").first end

    # Generate _bytes_ random bytes
    def random_bytes(bytes); OpenSSL::Random.random_bytes(bytes) end

    # Generate a random string _length_ long
    def random_string(length); random_bytes(length / 2).unpack("H*")[0] end

    # Generate an \OpenID signature
    def gen_sig(mac, params)
      signed = params["signed"].split(",").map {|k| [k, params[k]]}
      if mac.length == 20
        Signatures["HMAC-SHA1"].sign(  mac, kv_encode(signed))
      else
        Signatures["HMAC-SHA256"].sign(mac, kv_encode(signed))
      end
    end
  end

  module Signatures # :nodoc: all
    def self.[](name)
      @assocs ||= Hash[*constants.map {|c|
        a = const_get(c)
        [a.assoc, a] if a.respond_to? :assoc
      }.compact.flatten]
      @assocs[name]
    end

    class Assoc
      attr_reader :assoc
      def initialize(assoc, digest); @assoc, @digest = assoc.freeze, digest.new end
      def sign(mac, value); OpenSSL::HMAC.new(mac, @digest.reset).update(value).to_s end
      def size; @digest.size end
      def gen_mac; OpenID.random_bytes(@digest.size) end
    end

    HMAC_SHA1 = Assoc.new "HMAC-SHA1", OpenSSL::Digest::SHA1
    HMAC_SHA256 = Assoc.new "HMAC-SHA256", OpenSSL::Digest::SHA256
  end

  module DH # :nodoc: all
    DEFAULT_MODULUS=0xDCF93A0B883972EC0E19989AC5A2CE310E1D37717E8D9571BB7623731866E61EF75A2E27898B057F9891C2E27A639C3F29B60814581CD3B2CA3986D2683705577D45C2E7E52DC81C7A171876E5CEA74B1448BFDFAF18828EFD2519F14E45E3826634AF1949E5B535CC829A483B8A76223E5D490A257F05BDFF16F2FB22C583AB
    DEFAULT_GEN=2

    class SHA_ANY
      class MissingKey < StandardError; end

      attr_reader :session_name
      def compatible_key_size?(size); @digest.size == size end
      def initialize(session_name, digest); @session_name, @digest = session_name.freeze, digest.new end

      def to_hash(mac, p, g, consumer_public_key)
        raise MissingKey if consumer_public_key.nil?
        p ||= DEFAULT_MODULUS
        g ||= DEFAULT_GEN
        private_key, public_key = generate_pair(p,g)
        shared = compute_shared(consumer_public_key, private_key, p)
        shared_hashed = @digest.reset.update(OpenID.btwoc(shared)).digest
        {
          "dh_server_public" => OpenID.base64_encode(OpenID.btwoc(public_key)),
          "enc_mac_key" => OpenID.base64_encode(sxor(shared_hashed, mac))
        }
      end

      def compute_shared(pub, pri, p = DEFAULT_MODULUS); powermod(pub, pri, p) end

      def generate_pair(p = DEFAULT_MODULUS, g = DEFAULT_GEN)
        private_key = OpenID.random_string(p.to_s(16).size).to_i(16) % p
        public_key = powermod(g, private_key, p)
        [private_key, public_key]
      end

      private
      def sxor(s1, s2)
        # s1 = s1.to_enum(:each_byte); s2 = s2.to_enum(:each_byte)
        s1.bytes.zip(s2.bytes).map { |x,y| (x^y).chr }.join
      end

      # x ** n % p
      # Taken from http://blade.nagaokaut.ac.jp/cgi-bin/scat.rb/ruby/ruby-talk/19098
      # by Eric Lee Green.
      def powermod(x, n, q)
        y=1
        while n != 0
          y=(y*x) % q if n[0]==1
          n = n >> 1
          x = (x ** 2) % q
        end
        y
      end
    end

    SHA1   = SHA_ANY.new "DH-SHA1"  , OpenSSL::Digest::SHA1
    SHA256 = SHA_ANY.new "DH-SHA256", OpenSSL::Digest::SHA256

    class NoEncryption
      def self.compatible_key_size?(size); true end
      def self.session_name; "no-encryption" end
      def self.to_hash(mac, p, g, c); {"mac_key" => OpenID.base64_encode(mac)} end
    end

    def self.[](name)
      @sessions ||= Hash[*constants.map {|c|
        s = const_get(c)
        [s.session_name, s] if s.respond_to? :session_name
      }.compact.flatten]
      @sessions[name]
    end
  end
end


module Rack # :nodoc:
  # This is a Rack middleware, use it as such:
  #   Rack::Builder.new {
  #     use Rack::OpenIDProvider, custom_options
  #     run MyProvider.new
  #   }
  class OpenIDProvider
    class YadisServe
      DEFAULT_YADIS = %{
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
<XRD>
  <Service priority="0">
    %s
    %s
  </Service>
</XRD>
</xrds:XRDS>
}.freeze

      def initialize(options)
        @content = DEFAULT_YADIS % [
          options["Type"].map {|t| "<Type>" + t + "</Type>\n"}, 
          options["URI"].map {|u| "<URI>" + u + "</URI>\n"}
        ]
      end

      def call(env); [200, {"Content-Type" => "application/xrds+xml"}, [@content] ] end
    end

    # You should include this module in your Rack application like this:
    #  class MyProvider
    #    include Rack::OpenIDProvider::Utils
    #    
    #    def call(env)
    #      ... do stuff ...
    #    end
    #  end
    module Utils
      class NoReturnToRedirect < StandardError # :nodoc:
      end
      class NoIdentity < StandardError # :nodoc:
      end

      # Positive assertion by HTTP redirect
      def redirect_positive(env, params = {}); redirect_res env, gen_pos(env, params) end

      # Negative assertion by HTTP redirect
      def redirect_negative(env, params = {}); redirect_res env, gen_neg(env, params) end

      # Error response by HTTP redirect
      def redirect_error(env, error, params = {}); redirect_res env, gen_error(env, error, params) end
      
      def redirect_res(env, h) # :nodoc:
        openid = env['openid.provider.req']
        if d = URI(openid['return_to'])
          d.query = d.query ? d.query + "&" + OpenID.url_encode(h) : OpenID.url_encode(h)
          [301, {'Location' => d.to_s}, []]
        else
          raise NoReturnToRedirect
        end
      end

      # Generate a positive assertion HTML form
      def positive_htmlform(env, params= {}); gen_htmlform env, gen_pos(env, params) end

      # Generate a negative assertion HTML form
      def negative_htmlform(env, params= {}); gen_htmlform env, gen_neg(env, params) end

      # Generate an error HTML form
      def error_htmlform(env, error, params = {}); gen_htmlform env, gen_error(env, error, params) end

      def gen_htmlform(env, h) # :nodoc:
        openid = env['openid.provider.req']
        if d = Rack::Utils.escape(openid['return_to'])
          form = "<form name='openid_form' method='post' action='#{d}'>"
          h.each {|k,v| form << "<input type='hidden' name='openid.#{Rack::Utils.escape k}' value='#{Rack::Utils.escape v}' />"}
          form << "<input type='submit' /></form>"
        else
          raise NoReturnToRedirect
        end
      end

      def gen_pos(env, params = {}) # :nodoc:
        if params["claimed_id"] == OpenID::IDENTIFIER_SELECT or
            params["identity"] == OpenID::IDENTIFIER_SELECT
          raise NoIdentity
        end

        openid = env['openid.provider.req']
        invalidate_handle = env['openid.provider.invalidate_handle']
        assoc_handle = env['openid.provider.assoc_handle']
        mac = env['openid.provider.mac']
        nonce = env['openid.provider.nonce']
        options = env['openid.provider.options']
        r = params.merge(
          "ns" => OpenID::NS,
          "mode" => "id_res",
          "op_endpoint" => options['op_endpoint'] || Request.new(env).url,
          "return_to" => openid['return_to'],
          "response_nonce" => nonce,
          "assoc_handle" => assoc_handle
        )
        r["invalidate_handle"] = invalidate_handle if invalidate_handle
        if not r["signed"]
          r["signed"] = "op_endpoint,return_to,assoc_handle,response_nonce"
          r["signed"] << ",identity,claimed_id" if r["identity"] and r["claimed_id"]
        end
        r["sig"] = OpenID.gen_sig(mac, r)
        r
      end

      def gen_neg(env, params = {}) # :nodoc:
        openid = env['openid.provider.req']
        if openid['mode'] == "checkid_immediate"
          params.merge "ns" => OpenID::NS, "mode" => "setup_needed"
        else
          params.merge "ns" => OpenID::NS, "mode" => "cancel"
        end
      end

      def gen_error(env, error, params = {}) # :nodoc:
        options = env['openid.provider.options']
        error_res = {"ns" => OpenID::NS, "mode" => "error", "error" => error}
        error_res["contact"] = options["contact"] if options["contact"]
        error_res["reference"] = options["reference"] if options["reference"]
        error_res.merge(params)
      end
    end

    include Utils
    no_openid = lambda {|env| [400, {"Content-Type" => "text/plain"}, ["Invalid OpenID Request"]]}

    DEFAULT_OPTIONS = {
      'handle_timeout' => 36000,
      'private_handle_timeout' => 300,
      'nonce_timeout' => 300,
      'checkid_immediate' => false,
      'no_openid' => no_openid
    }

    def initialize(app, options = {})
      @app = app
      @options = DEFAULT_OPTIONS.merge(options)
      @handles, @private_handles, @nonces = {}, {}, {}
    end

    def call(env)
      req = Request.new(env)
      openid = open_id_params(req.params)
      env['openid.provider.req'] = openid
      env['openid.provider.options'] = @options
      clean_handles

      case openid['mode']
      when 'associate'
        associate(env, openid)
      when 'checkid_immediate'
        if @options['checkid_immediate']
          checkid(env, openid)
          @app.call(env)
        else
          redirect_negative(env)
        end
      when 'checkid_setup'
        checkid(env, openid)
        @app.call(env)
      when 'check_authentication'
        check_authentication(env, openid)
      else
        s,h,b = (@options['no_openid'] || @app).call(env)
        h['X-XRDS-Location'] = @options['xrds_location'] if @options['xrds_location']
        [s,h,b]
      end
    end

    private
    def clean_handles; end
    
    def associate(env, openid)
      dh_modulus, dh_gen, dh_consumer_public = openid['dh_modulus'], openid['dh_gen'], openid['dh_consumer_public']
      p = dh_modulus && OpenID.ctwob(OpenID.base64_decode(dh_modulus))
      g = dh_gen && OpenID.ctwob(OpenID.base64_decode(dh_gen))
      consumer_public_key = dh_consumer_public && OpenID.ctwob(OpenID.base64_decode(dh_consumer_public))

      session_type = OpenID::DH[openid['session_type']]
      assoc_type = OpenID::Signatures[openid['assoc_type']]

      if session_type.nil? or assoc_type.nil?
        return direct_error(env, "session type or association type not supported", "error_code" => "unsupported-type")
      elsif not session_type.compatible_key_size?(assoc_type.size)
        return direct_error(env, "session type and association type are incompatible")
      end
      
      mac = assoc_type.gen_mac
      handle = gen_handle
      r = {
        "assoc_handle" => handle,
        "session_type" => openid['session_type'],
        "assoc_type" => openid['assoc_type'],
        "expires_in" => @options['handle_timeout']
      }
      
      begin
        r.update session_type.to_hash(mac, p, g, consumer_public_key)
      rescue OpenID::DH::SHA_ANY::MissingKey
        return direct_error(env, "dh_consumer_public missing")
      end
      
      @handles[handle] = mac
      direct_response env, r
    end

    def checkid(env, openid)
      assoc_handle = openid['assoc_handle']
      if mac = @handles[assoc_handle]
        env['openid.provider.assoc_handle'] = assoc_handle
        env['openid.provider.mac'] = mac
      else
        env['openid.provider.invalidate_handle'] = assoc_handle
        env['openid.provider.assoc_handle'] = assoc_handle = gen_handle
        env['openid.provider.mac'] = @private_handles[assoc_handle] = OpenID::Signatures["HMAC-SHA256"].gen_mac
      end
      env['openid.provider.nonce'] = nonce = gen_nonce
      @nonces[nonce] = assoc_handle
    end
    
    def check_authentication(env, openid)
      assoc_handle = openid['assoc_handle']
      invalidate_handle = openid['invalidate_handle']
      nonce = openid['response_nonce']

      # Check if assoc_handle, nonce and signature are valid. Then delete the response nonce
      if mac = @private_handles[assoc_handle] and @nonces.delete(nonce) == assoc_handle and OpenID.gen_sig(mac, openid) == openid['sig']
        r = {"is_valid" => "true"}
        r["invalidate_handle"] = invalidate_handle if invalidate_handle && @handles[invalidate_handle].nil?
        direct_response  env, r
      else
        direct_response env, "is_valid" => "false"
      end
    end

    def open_id_params(params)
      openid_params = {}
      params.each { |k,v| openid_params[$'] = v if k =~ /^openid\./ }
      openid_params
    end
    
    def direct_response(env, params)
      [
        200,
        {"Content-Type" => "text/plain"},
        [OpenID.kv_encode(params.merge("ns" => OpenID::NS))]
      ]
    end

    def direct_error(env, error, params = {})
      [
        400,
        {"Content-Type" => "text/plain"},
        [OpenID.kv_encode(gen_error(env, error, params))]
      ]
    end
    
    def gen_handle; Time.now.utc.iso8601 + OpenID.random_string(6) end
    def gen_nonce;  Time.now.utc.iso8601 + OpenID.random_string(6) end
  end
end
