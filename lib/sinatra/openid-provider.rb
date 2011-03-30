require 'sinatra/base'
require 'rack/openid-provider'

module Sinatra
  module OpenIDProvider
    
    module Helpers
      def oip_request; Rack::OpenIDProvider::OpenIDRequest.new(env) end
      def oip_response; @oip_response ||= Rack::OpenIDProvider::OpenIDResponse.new end
      def oip_html_fields(h) Rack::OpenIDProvider::OpenIDResponse.gen_html_fields(h) end
    end
   
    def route_openid(mode, &block)
      openid_modes[mode] = true
      get  "/", :openid_mode => mode, &block
      post "/", :openid_mode => mode, &block
    end
    
    # OpenID Request modes
    def associate(&block) route_openid("associate", &block) end
    def checkid_setup(&block) route_openid("checkid_setup", &block) end
    def checkid_immediate(&block) route_openid("checkid_immediate", &block) end
    def check_authentication(&block) route_openid("check_authentication", &block) end
    
    def self.registered(app)
      app.helpers Helpers
      app.set(:openid_mode) { |value| condition { oip_request.valid? and oip_request.mode == value } }
      app.set(:openid_modes, {})
      
      app.before do
        raise NotFound if oip_request.valid? and !settings.openid_modes[oip_request.mode]
      end
    end
  end
  
  register OpenIDProvider
end
