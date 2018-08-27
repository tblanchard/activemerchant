module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    # For more information on the Paytrace Gateway please visit their {Integration Center}[https://developers.paytrace.com]
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
    class PayTraceGateway < Gateway

      # Creates a new PayTraceGateway
      #

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
        billing_address = options[:billing_address]

        params = {
          :amount => money/100.0,
          :card_number => creditcard.number,
          :exipration_month => creditcard.month,
          :expiration_year => creditcard.year,
          :csc => creditcard.verification_value,
          :billing_name => billing_address[:name],
          :billing_address => billing_address[:address1],
          :billing_address2 => billing_address[:address2],
          :billing_city => billing_address[:city],
          :billing_state => billing_address[:state],
          :billing_postal_code => billing_address[:zip],
          :billing_country => billing_address[:country]
        }

        response = PayTrace::Transaction.keyed_authorization(params)

        ActiveMerchant::Billing::Response.new(response.values['success'],response.values['status_message'],response.values,response.values)
      end

      # Perform a purchase, which is essentially an authorization and capture in a single operation.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be purchased. Either an Integer value in cents or a Money object.
      # * <tt>creditcard</tt> -- The CreditCard details for the transaction.
      # * <tt>options</tt> -- A hash of optional parameters.
      def purchase(money, creditcard, options = {})
        billing_address = options[:billing_address]

        params = {
          :amount => money/100.0,
          :card_number => creditcard.number,
          :exipration_month => creditcard.month,
          :expiration_year => creditcard.year,
          :csc => creditcard.verification_value,
          :billing_name => billing_address[:name],
          :billing_address => billing_address[:address1],
          :billing_address2 => billing_address[:address2],
          :billing_city => billing_address[:city],
          :billing_state => billing_address[:state],
          :billing_postal_code => billing_address[:zip],
          :billing_country => billing_address[:country]
        }

        response = PayTrace::Transaction.keyed_sale(params)

        ActiveMerchant::Billing::Response.new(response.values['success'],response.values['status_message'],response.values,response.values)
      end

      # Captures the funds from an authorized transaction.
      #
      # ==== Parameters
      #
      # * <tt>money</tt> -- The amount to be captured.  Either an Integer value in cents or a Money object.
      # * <tt>authorization</tt> -- The authorization returned from the previous authorize request.
      def capture(money, authorization, options = {})

        params = { 
          :transaction_id => authorization,
          :amount => money/100.0 }
        response = PayTrace::Transaction.capture(params)
        ActiveMerchant::Billing::Response.new(response.values['success'],response.values['status_message'],response.values,response.values)
      end

      # Void a previous transaction
      #
      # ==== Parameters
      #
      # * <tt>authorization</tt> - The authorization returned from the previous authorize request.
      def void(authorization, options = {})
        response = PayTrace::Transaction.void({:transaction_id => authorization})

        ActiveMerchant::Billing::Response.new(response.values['success'],response.values['status_message'],response.values,response.values)
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
        params = {:amount => money/100.0, :transaction_id => identification }
        response = PayTrace::Transaction.void(params)
        ActiveMerchant::Billing::Response.new(response.values['success'],response.values['status_message'],response.values,response.values)
      end

  end
end
