require 'sinatra/base'
require 'rack/openid-provider'

module Sinatra
  module OpenIDProvider
    
    module Helpers
      def oip_request; Rack::OpenIDRequest.new(env) end
      def oip_response; @oip_response ||= Rack::OpenIDResponse.new(env) end
      def oip_html_fields(h) Rack::OpenIDResponse.gen_html_fields(h) end
    end
   
    def checkid_setup(&block)
      get  "/", :openid_mode => "checkid_setup", &block
      post "/", :openid_mode => "checkid_setup", &block
    end
       
    def checkid_immediate(&block)
      get  "/", :openid_mode => "checkid_immediate", &block
      post "/", :openid_mode => "checkid_immediate", &block
    end
    
    def self.registered(app)
      app.helpers OpenIDProvider::Helpers
      app.set(:openid_mode) { |value| condition { oip_request.mode == value } }
    end
  end
  
  register OpenIDProvider
end
