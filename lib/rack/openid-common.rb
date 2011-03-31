require 'rack'
require 'openssl'
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
          raise InvalidAssociation if enc_mac_key.size != size

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
      def dh_consumer_public=(key); params['dh_consumer_public'] = OpenID.base64_encode(OpenID.btwoc(key)) end
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
end