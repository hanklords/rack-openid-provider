module ::Rack
class OpenIDRequest
  class Sreg
    PREFIX="sreg".freeze
    FIELDS = %w(required optional policy_url).freeze
    FIELD_SIGNED = %w(nickname email fullname dob gender postcode country language timezone).freeze
    
    def initialize(params) @params = params end
    def required; (@params["sreg.required"] || "").split(",") end
    def optional; (@params["sreg.optional"] || "").split(",") end
    def requested; optional + required end
    def policy_url; @params["sreg.policy_url"] || "" end
  end
  
  Sreg::FIELD_SIGNED.each { |field| OpenIDResponse::FIELD_SIGNED << "#{Sreg::PREFIX}.#{field}" }
  def sreg; @env['openid.provider.request.params.sreg'] ||= Rack::OpenIDRequest::Sreg.new(params) end
end
end
