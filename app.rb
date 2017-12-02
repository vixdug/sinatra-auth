require 'shopify_api'
require 'sinatra'
require 'httparty'
require 'dotenv'
require 'openssl'
require 'base64'
require 'pry'
Dotenv.load

API_KEY = ENV['API_KEY']
API_SECRET = ENV['API_SECRET']
APP_URL = 'https://b65ca259.ngrok.io'

class VixApp < Sinatra::Base
    attr_reader :tokens

  def initialize
    @@tokens = {}
    super
  end

  get '/' do
     # allows your app to load in the shopify admin as opposed to a new window.
      headers({'X-Frame-Options' => ''})
     erb :index
   end

	get '/install' do
    shop = request.params['shop']
    scopes = "read_orders,read_products,write_products"

     install_url =
       "https://#{shop}/admin/oauth/authorize?client_id=#{API_KEY}&scope=#{scopes}"\
       "&redirect_uri=#{APP_URL}/auth"

     redirect install_url
	end

  get '/auth' do

     # when the merchant clicks on 'install' a params hash is generated with hmac, code, shop, and timestamp
     hmac = params['hmac']
     # assinging params as values to each key in the hash
     h = {
       shop: params['shop'],
       code: params['code'],
       timestamp: params['timestamp']
     }
     # creating an authorization string that checks to see if the hmac generated
     # by the app is the same as what Shopify provided - ensures the request came from Shopify
     h = h.map {|k,v| "#{k}=#{v}"}.sort.join("&")
     # putting 'h' through a OpenSSL method to create a digest to compare to the hmac
     # OpenSSL::Digest.new('sha256') - creates a new digest instance
     digest = OpenSSL::Digest.new('sha256')
     # creating a post request using the api info and hmac to generate an access token
     # as long as the hmac matches the digest
     digest = OpenSSL::HMAC::hexdigest(digest, API_SECRET, h)


     url = "https://#{params['shop']}/admin/oauth/access_token"
     data = {
       client_id: API_KEY,
       client_secret: API_SECRET,
       code: params['code']
     }
     # storing the result of the post request in a response variable
     # response includes the app scope, and the access token in a hash
     # the access token gives you permission to make api calls on a shop
     response = HTTParty.post(url, body: data)

     if hmac == digest

       # make sure to parse the body of the response - otherwise you will not
       # be able to properly set a token for the shop
       response = JSON.parse(response.body)
       @@tokens[params['shop']] = response['access_token']
       redirect "/"
        else
       status [403, "You did something wrong, you should probably check your code"]
       end
   end

 end


VixApp.run!
