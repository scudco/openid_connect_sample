class AuthorizationsController < ApplicationController
  rescue_from Rack::OAuth2::Server::Authorize::BadRequest do |e|
    @error = e
    logger.info e.backtrace[0,10].join("\n")
    render :error, status: e.status
  end

  def new
    @endpoint = AuthorizationEndpoint.new(current_account)

    process_endpoint
  end

  def create
    @endpoint = AuthorizationEndpoint.new(
      current_account,
      allow_approval: true,
      user_approved: params[:approve]
    )

    process_endpoint
  end

  private
  def process_endpoint
    status, header, resp = @endpoint.call(request.env)

    require_authentication

    if @endpoint.login_expired?
      flash[:notice] = 'Exceeded Max Age, Login Again'
      unauthenticate!
      require_authentication
    end

    www_auth_key = "WWW-Authenticate"
    www_auth = header[www_auth_key]
    headers[www_auth_key] = www_auth if www_auth.present?

    if resp.redirect?
      redirect_to header['Location']
    else
      render :new
    end
  end
end
