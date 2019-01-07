module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # For more information on the Elavon Converge Gateway please visit their {Integration Center}[https://developer.elavon.com]
    #
    # The login and password are not the username and password you use to 
    # login to the Authorize.Net Merchant Interface. Instead, you will 
    # use the API Login ID as the login and Transaction Key as the 
    # password.
    # 
    # ==== How to Get Your API Login ID and Transaction Key
    #
    # 1. Log into the Merchant Interface
    # 2. Select Settings from the Main Menu
    # 3. Click on API Login ID and Transaction Key in the Security section
    # 4. Type in the answer to the secret question configured on setup
    # 5. Click Submit
    # 
    # ==== Automated Recurring Billing (ARB)
    # 
    # Automated Recurring Billing (ARB) is an optional service for submitting and managing recurring, or subscription-based, transactions.
    # 
    # To use recurring, update_recurring, and cancel_recurring ARB must be enabled for your account.
    # 
    # Information about ARB is available on the {Authorize.Net website}[http://www.authorize.net/solutions/merchantsolutions/merchantservices/automatedrecurringbilling/].
    # Information about the ARB API is available at the {Authorize.Net Integration Center}[http://developer.authorize.net/]
    class ElavonConvergeGateway < Gateway
      require 'rest-client'
      require 'nokogiri'

      TEST_URL = 'https://demo.convergepay.com/VirtualMerchantDemo/processxml.do'
      LIVE_URL = 'https://api.convergepay.com/VirtualMerchant/processxml.do'


      # Creates a new PayTraceGateway
      #
      def initialize(options = {})
        requires!(options, :test, :ssl_merchant_id, :ssl_user_id, :ssl_pin)
        @options = options
        super
      end

      def url
        #@options[:test] ? TEST_URL : LIVE_URL
        LIVE_URL
      end

      def credentials
        @options.dup
      end

      def request_failed?(doc)
        doc.search(:errorcode).present?
      end

      def request_failed_response(doc)
        ActiveMerchant::Billing::Response.new(
          false,
          doc.search(:errormessage).text,
          {},
          @options)    
      end

      # Performs an authorization, which reserves the funds on the customer's credit card, but does not
      # charge the card.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be authorized. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      #  # Optional parameters:
      # * *:billing_name* -- the billing name for this transaction
      # * *:billing_address* -- the billing street address for this transaction
      # * *:billing_address2* -- the billing street address second line (e.g., apartment, suite) for this transaction
      # * *:billing_city* -- the billing city for this transaction
      # * *:billing_state* -- the billing state for this transaction
      # * *:billing_postal_code* -- the billing zip code for this transaction
      # * *:billing_country* -- the billing country for this transaction
      # * *:shipping_name* -- the shipping name for this transaction
      # * *:shipping_address* -- the shipping street address for this transaction
      # * *:shipping_address2* -- the shipping street address second line (e.g., apartment, suite) for this transaction
      # * *:shipping_city* -- the shipping city for this transaction
      # * *:shipping_state* -- the shipping state for this transaction
      # * *:shipping_postal_code* -- the shipping zip code for this transaction
      # * *:shipping_region* -- the shipping region (e.g. county) for this transaction
      # * *:shipping_country* -- the shipping country for this transaction
      # * *:email* -- the customer email for this transaction
      # * *:csc* -- credit card security code (customer ID token or referenced transaction sale)
      # * *:invoice* -- an internal invoice number (customer ID token or referenced transaction sale)
      # * *:description* -- a description of the sale (customer ID token or referenced transaction sale)
      # * *:tax_amount* -- the amount of tax on the sale (customer ID token or referenced transaction sale)
      # * *:customer_reference_id* -- a customer reference ID (customer ID token or referenced transaction sale)
      # * *:discretionary_data* -- a hash of optional discretionary data to attach to this transaction
      # * *:return_clr* -- if set to "Y", card level results will be returned w/ the response. Card level results include whether or not the card is a consumer, purchasing, check, rewards, etc. account. Card level results are only returned with requests to process sales or authorizations through accounts on the TSYS/Vital, Heartland, Global, Paymentech, and Trident networks.(customer ID token sale)
      # * *:custom_dba* -- optional value that is sent to the cardholder’s issuer and overrides the business name stored in PayTrace. Custom DBA values are only used with requests to process sales or authorizations through accounts on the TSYS/Vital, Heartland, and Trident networks (customer ID token sale)
      # * *:enable_partial_authentication* -- flag that must be set to ‘Y’ in order to support partial autho
      def authorize(money, creditcard, options = {})
        
        body = credentials
        body[:ssl_transaction_type] = :ccauthonly
        body[:ssl_amount] = '%.2f' % (money / 100.0)

        body[:ssl_card_number] = creditcard.number
        body[:ssl_exp_date] = ('%02d' % creditcard.month.to_i)+('%02d' % (creditcard.year.to_i % 1000))
        body[:ssl_first_name] = creditcard.first_name
        body[:ssl_last_name] = creditcard.last_name

        if creditcard.verification_value.present?
          body[:ssl_cvv2cvc2] = creditcard.verification_value
          body[:ssl_cvv2cvc2_indicator] = 1
        end

        billing_address = options[:billing_address]

        if billing_address.present?
          body[:ssl_avs_zip] = billing_address[:zip]
          body[:ssl_avs_address] = billing_address[:address1]
          body[:ssl_city] = billing_address[:city]
          body[:ssl_state] = billing_address[:state]
          body[:ssl_country] = billing_address[:country]
        end

        response = RestClient.post(url, xmlize({:txn => body})) {|response, request, result| response }
        doc = ::Nokogiri::HTML(response)

        return request_failed_response(doc) if request_failed?(doc)

        ActiveMerchant::Billing::Response.new(
          doc.search(:ssl_result).text.to_i == 0,
          doc.search(:ssl_result_message).text, {},
          :authorization => doc.search(:ssl_txn_id).text,
          :approval_code => doc.search(:ssl_approval_code).text,
          :avs_result => doc.search(:ssl_avs_response).text,
          :cvv_result => doc.search(:ssl_cvv2_response).text)
      end

      # Perform a purchase, which is essentially an authorization and capture in a single operation.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be purchased. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      def purchase(money, creditcard, options = {})

        body = credentials
        body[:ssl_transaction_type] = :ccsale
        body[:ssl_amount] = '%.2f' % (money / 100.0)

        body[:ssl_card_number] = creditcard.number
        body[:ssl_exp_date] = ('%02d' % creditcard.month.to_i)+('%02d' % (creditcard.year.to_i % 1000))
        body[:ssl_first_name] = creditcard.first_name
        body[:ssl_last_name] = creditcard.last_name

        if creditcard.verification_value.present?
          body[:ssl_cvv2cvc2] = creditcard.verification_value
          body[:ssl_cvv2cvc2_indicator] = 1
        end

        billing_address = options[:billing_address]

        if billing_address.present?
          body[:ssl_avs_zip] = billing_address[:zip]
          body[:ssl_avs_address] = billing_address[:address1]
          body[:ssl_city] = billing_address[:city]
          body[:ssl_state] = billing_address[:state]
          body[:ssl_country] = billing_address[:country]
        end

        body_text = xmlize({:txn => body})

        response = RestClient.post(url, body_text) {|response, request, result| response }
        logger.error body_text
        logger.error response.to_s
        doc = ::Nokogiri::HTML(response)

        return request_failed_response(doc) if request_failed?(doc)

        ActiveMerchant::Billing::Response.new(
          (doc.search(:ssl_result).text.to_i == 0),
          doc.search(:ssl_result_message).text, {},
          :authorization => doc.search(:ssl_txn_id).text,
          :approval_code => doc.search(:ssl_approval_code).text,
          :avs_result => doc.search(:ssl_avs_response).text,
          :cvv_result => doc.search(:ssl_cvv2_response).text)
      end

      # Captures the funds from an authorized transaction.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be captured.  Either an Integer value in cents or a Money object.
      # * <tt>authorization</tt> -- The authorization returned from the previous authorize request.
      def capture(money, authorization, options = {})

        body = credentials
        body[:ssl_transaction_type] = :cccomplete

        body[:ssl_amount] = (money.to_money/100.0).to_s
        body[:ssl_txn_id] = authorization

        response = RestClient.post(url, xmlize({:txn => body})) {|response, request, result| response }
        doc = ::Nokogiri::HTML(response)

        return request_failed_response(doc) if request_failed?(doc)

        ActiveMerchant::Billing::Response.new(
          doc.search(:ssl_result).text.to_i == 0,
          doc.search(:ssl_result_message).text, {},
          :authorization => doc.search(:ssl_txn_id).text)
      end

      # Void a previous transaction
      #
      # ==== Parameters
      #
      # * <tt>authorization</tt> - The authorization returned from the previous authorize request.
      def void(authorization, options = {})
        body = credentials
        body[:ssl_transaction_type] = :ccvoid

        body[:ssl_txn_id] = authorization

        response = RestClient.post(url, xmlize({:txn => body})) {|response, request, result| response }
        doc = ::Nokogiri::HTML(response)

        return request_failed_response(doc) if request_failed?(doc)

        ActiveMerchant::Billing::Response.new(
          doc.search(:ssl_result).text.to_i == 0,
          doc.search(:ssl_result_message).text, {},
          :authorization => doc.search(:ssl_txn_id).text)
      end

      # Credit an account.
      #
      # This transaction is also referred to as a Refund and indicates to the gateway that
      # money should flow from the merchant to the customer.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be credited to the customer. Either an Integer value in cents or a Money object.
      # * <tt>identification</tt> -- The ID of the original transaction against which the credit is being issued.
      # * <tt>options</tt> -- A hash of parameters.
      #
      # ==== Options
      #
      # * <tt>:card_number</tt> -- The credit card number the credit is being issued to. (REQUIRED)
      def credit(money, identification, options = {})
        body = credentials
        body[:ssl_transaction_type] = :cccredit

        body[:ssl_amount] = (money.to_money/100.0).to_s
        body[:ssl_txn_id] = identification

        response = RestClient.post(url, xmlize({:txn => body})) {|response, request, result| response }
        doc = ::Nokogiri::HTML(response)

        return request_failed_response(doc) if request_failed?(doc)

        ActiveMerchant::Billing::Response.new(
          doc.search(:ssl_result).text.to_i == 0,
          doc.search(:ssl_result_message).text, {},
          :authorization => doc.search(:ssl_txn_id).text)
      end

      def settle
      end

      def xmlize(args)
        if args.is_a?(Hash)
          xml = ''
          args.each_pair { |name, val|  xml += "<#{name}>#{xmlize(val)}</#{name}>" }
          return xml
        end
        args.to_s
      end
    end
  end
end
