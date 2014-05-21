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

    respond_as_rack_app(status, header, resp)
  end

  def respond_as_rack_app(status, header, response)
    ["WWW-Authenticate"].each do |key|
      headers[key] = header[key] if header[key].present?
    end

    if response.redirect?
      redirect_to header['Location']
    else
      render :new
    end
  end
end
