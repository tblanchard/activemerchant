--- !ruby/object:Gem::Specification 
name: activemerchant
version: !ruby/object:Gem::Version 
  hash: 6
  segments: 
  - 1
  - 6
  - 9
  version: 1.6.9
platform: ruby
authors: 
- Tobias Luetke
autorequire: 
bindir: bin
cert_chain: 
- |
  -----BEGIN CERTIFICATE-----
  MIIDNjCCAh6gAwIBAgIBADANBgkqhkiG9w0BAQUFADBBMRMwEQYDVQQDDApjb2R5
  ZmF1c2VyMRUwEwYKCZImiZPyLGQBGRYFZ21haWwxEzARBgoJkiaJk/IsZAEZFgNj
  b20wHhcNMDcwMjIyMTcyMTI3WhcNMDgwMjIyMTcyMTI3WjBBMRMwEQYDVQQDDApj
  b2R5ZmF1c2VyMRUwEwYKCZImiZPyLGQBGRYFZ21haWwxEzARBgoJkiaJk/IsZAEZ
  FgNjb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6T4Iqt5iWvAlU
  iXI6L8UO0URQhIC65X/gJ9hL/x4lwSl/ckVm/R/bPrJGmifT+YooFv824N3y/TIX
  25o/lZtRj1TUZJK4OCb0aVzosQVxBHSe6rLmxO8cItNTMOM9wn3thaITFrTa1DOQ
  O3wqEjvW2L6VMozVfK1MfjL9IGgy0rCnl+2g4Gh4jDDpkLfnMG5CWI6cTCf3C1ye
  ytOpWgi0XpOEy8nQWcFmt/KCQ/kFfzBo4QxqJi54b80842EyvzWT9OB7Oew/CXZG
  F2yIHtiYxonz6N09vvSzq4CvEuisoUFLKZnktndxMEBKwJU3XeSHAbuS7ix40OKO
  WKuI54fHAgMBAAGjOTA3MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgSwMB0GA1UdDgQW
  BBR9QQpefI3oDCAxiqJW/3Gg6jI6qjANBgkqhkiG9w0BAQUFAAOCAQEAs0lX26O+
  HpyMp7WL+SgZuM8k76AjfOHuKajl2GEn3S8pWYGpsa0xu07HtehJhKLiavrfUYeE
  qlFtyYMUyOh6/1S2vfkH6VqjX7mWjoi7XKHW/99fkMS40B5SbN+ypAUst+6c5R84
  w390mjtLHpdDE6WQYhS6bFvBN53vK6jG3DLyCJc0K9uMQ7gdHWoxq7RnG92ncQpT
  ThpRA+fky5Xt2Q63YJDnJpkYAz79QIama1enSnd4jslKzSl89JS2luq/zioPe/Us
  hbyalWR1+HrhgPoSPq7nk+s2FQUBJ9UZFK1lgMzho/4fZgzJwbu+cO8SNuaLS/bj
  hPaSTyVU0yCSnw==
  -----END CERTIFICATE-----

date: 2008-12-08 00:00:00 Z
dependencies: 
- !ruby/object:Gem::Dependency 
  name: activesupport
  requirement: &id001 !ruby/object:Gem::Requirement 
    requirements: 
    - - ">="
      - !ruby/object:Gem::Version 
        hash: 5
        segments: 
        - 1
        - 4
        - 1
        version: 1.4.1
    version: 
  type: :runtime
  version_requirement: 
  version_requirements: *id001
- !ruby/object:Gem::Dependency 
  name: builder
  requirement: &id002 !ruby/object:Gem::Requirement 
    requirements: 
    - - ">="
      - !ruby/object:Gem::Version 
        hash: 15
        segments: 
        - 2
        - 0
        - 0
        version: 2.0.0
    version: 
  type: :runtime
  version_requirement: 
  version_requirements: *id002
description: 
email: tobi@leetsoft.com
executables: []

extensions: []

extra_rdoc_files: []

files: 
- lib/active_merchant
- lib/active_merchant/billing
- lib/active_merchant/billing/avs_result.rb
- lib/active_merchant/billing/base.rb
- lib/active_merchant/billing/check.rb
- lib/active_merchant/billing/credit_card.rb
- lib/active_merchant/billing/credit_card_formatting.rb
- lib/active_merchant/billing/credit_card_methods.rb
- lib/active_merchant/billing/cvv_result.rb
- lib/active_merchant/billing/expiry_date.rb
- lib/active_merchant/billing/gateway.rb
- lib/active_merchant/billing/gateways
- lib/active_merchant/billing/gateways/authorize_net.rb
- lib/active_merchant/billing/gateways/authorize_net_cim.rb
- lib/active_merchant/billing/gateways/beanstream
- lib/active_merchant/billing/gateways/beanstream/beanstream_core.rb
- lib/active_merchant/billing/gateways/beanstream.rb
- lib/active_merchant/billing/gateways/beanstream_interac.rb
- lib/active_merchant/billing/gateways/bogus.rb
- lib/active_merchant/billing/gateways/braintree.rb
- lib/active_merchant/billing/gateways/card_stream.rb
- lib/active_merchant/billing/gateways/cyber_source.rb
- lib/active_merchant/billing/gateways/data_cash.rb
- lib/active_merchant/billing/gateways/efsnet.rb
- lib/active_merchant/billing/gateways/elavon_converge.rb
- lib/active_merchant/billing/gateways/eway.rb
- lib/active_merchant/billing/gateways/exact.rb
- lib/active_merchant/billing/gateways/linkpoint.rb
- lib/active_merchant/billing/gateways/modern_payments.rb
- lib/active_merchant/billing/gateways/modern_payments_cim.rb
- lib/active_merchant/billing/gateways/moneris.rb
- lib/active_merchant/billing/gateways/net_registry.rb
- lib/active_merchant/billing/gateways/netbilling.rb
- lib/active_merchant/billing/gateways/pay_junction.rb
- lib/active_merchant/billing/gateways/pay_secure.rb
- lib/active_merchant/billing/gateways/payflow
- lib/active_merchant/billing/gateways/payflow/payflow_common_api.rb
- lib/active_merchant/billing/gateways/payflow/payflow_express_response.rb
- lib/active_merchant/billing/gateways/payflow/payflow_response.rb
- lib/active_merchant/billing/gateways/payflow.rb
- lib/active_merchant/billing/gateways/payflow_express.rb
- lib/active_merchant/billing/gateways/payflow_express_uk.rb
- lib/active_merchant/billing/gateways/payflow_uk.rb
- lib/active_merchant/billing/gateways/payment_express.rb
- lib/active_merchant/billing/gateways/paypal
- lib/active_merchant/billing/gateways/paypal/paypal_common_api.rb
- lib/active_merchant/billing/gateways/paypal/paypal_express_response.rb
- lib/active_merchant/billing/gateways/paypal.rb
- lib/active_merchant/billing/gateways/paypal_ca.rb
- lib/active_merchant/billing/gateways/paypal_express.rb
- lib/active_merchant/billing/gateways/paypal_express_common.rb
- lib/active_merchant/billing/gateways/paytrace.rb
- lib/active_merchant/billing/gateways/plugnpay.rb
- lib/active_merchant/billing/gateways/protx.rb
- lib/active_merchant/billing/gateways/psigate.rb
- lib/active_merchant/billing/gateways/psl_card.rb
- lib/active_merchant/billing/gateways/quickpay.rb
- lib/active_merchant/billing/gateways/realex.rb
- lib/active_merchant/billing/gateways/sage
- lib/active_merchant/billing/gateways/sage/sage_bankcard.rb
- lib/active_merchant/billing/gateways/sage/sage_core.rb
- lib/active_merchant/billing/gateways/sage/sage_virtual_check.rb
- lib/active_merchant/billing/gateways/sage.rb
- lib/active_merchant/billing/gateways/secure_pay.rb
- lib/active_merchant/billing/gateways/secure_pay_au.rb
- lib/active_merchant/billing/gateways/secure_pay_tech.rb
- lib/active_merchant/billing/gateways/skip_jack.rb
- lib/active_merchant/billing/gateways/trans_first.rb
- lib/active_merchant/billing/gateways/tran_cloud.rb
- lib/active_merchant/billing/gateways/trust_commerce.rb
- lib/active_merchant/billing/gateways/usa_epay.rb
- lib/active_merchant/billing/gateways/verifi.rb
- lib/active_merchant/billing/gateways/viaklix.rb
- lib/active_merchant/billing/gateways/wirecard.rb
- lib/active_merchant/billing/gateways.rb
- lib/active_merchant/billing/integrations
- lib/active_merchant/billing/integrations/action_view_helper.rb
- lib/active_merchant/billing/integrations/bogus
- lib/active_merchant/billing/integrations/bogus/helper.rb
- lib/active_merchant/billing/integrations/bogus/notification.rb
- lib/active_merchant/billing/integrations/bogus/return.rb
- lib/active_merchant/billing/integrations/bogus.rb
- lib/active_merchant/billing/integrations/chronopay
- lib/active_merchant/billing/integrations/chronopay/helper.rb
- lib/active_merchant/billing/integrations/chronopay/notification.rb
- lib/active_merchant/billing/integrations/chronopay/return.rb
- lib/active_merchant/billing/integrations/chronopay.rb
- lib/active_merchant/billing/integrations/gestpay
- lib/active_merchant/billing/integrations/gestpay/common.rb
- lib/active_merchant/billing/integrations/gestpay/helper.rb
- lib/active_merchant/billing/integrations/gestpay/notification.rb
- lib/active_merchant/billing/integrations/gestpay/return.rb
- lib/active_merchant/billing/integrations/gestpay.rb
- lib/active_merchant/billing/integrations/helper.rb
- lib/active_merchant/billing/integrations/hi_trust
- lib/active_merchant/billing/integrations/hi_trust/helper.rb
- lib/active_merchant/billing/integrations/hi_trust/notification.rb
- lib/active_merchant/billing/integrations/hi_trust/return.rb
- lib/active_merchant/billing/integrations/hi_trust.rb
- lib/active_merchant/billing/integrations/nochex
- lib/active_merchant/billing/integrations/nochex/helper.rb
- lib/active_merchant/billing/integrations/nochex/notification.rb
- lib/active_merchant/billing/integrations/nochex/return.rb
- lib/active_merchant/billing/integrations/nochex.rb
- lib/active_merchant/billing/integrations/notification.rb
- lib/active_merchant/billing/integrations/paypal
- lib/active_merchant/billing/integrations/paypal/helper.rb
- lib/active_merchant/billing/integrations/paypal/notification.rb
- lib/active_merchant/billing/integrations/paypal/return.rb
- lib/active_merchant/billing/integrations/paypal.rb
- lib/active_merchant/billing/integrations/return.rb
- lib/active_merchant/billing/integrations/two_checkout
- lib/active_merchant/billing/integrations/two_checkout/helper.rb
- lib/active_merchant/billing/integrations/two_checkout/notification.rb
- lib/active_merchant/billing/integrations/two_checkout/return.rb
- lib/active_merchant/billing/integrations/two_checkout.rb
- lib/active_merchant/billing/integrations.rb
- lib/active_merchant/billing/response.rb
- lib/active_merchant/lib
- lib/active_merchant/lib/country.rb
- lib/active_merchant/lib/error.rb
- lib/active_merchant/lib/post_data.rb
- lib/active_merchant/lib/posts_data.rb
- lib/active_merchant/lib/requires_parameters.rb
- lib/active_merchant/lib/utils.rb
- lib/active_merchant/lib/validateable.rb
- lib/active_merchant.rb
- lib/certs
- lib/certs/cacert.pem
- lib/support
- lib/support/gateway_support.rb
- lib/tasks
- lib/tasks/cia.rb
- test/extra
- test/extra/binding_of_caller.rb
- test/extra/breakpoint.rb
- test/fixtures.yml
- test/remote
- test/remote/gateways
- test/remote/gateways/remote_authorize_net_cim_test.rb
- test/remote/gateways/remote_authorize_net_test.rb
- test/remote/gateways/remote_beanstream_interac_test.rb
- test/remote/gateways/remote_beanstream_test.rb
- test/remote/gateways/remote_braintree_test.rb
- test/remote/gateways/remote_card_stream_test.rb
- test/remote/gateways/remote_cyber_source_test.rb
- test/remote/gateways/remote_data_cash_test.rb
- test/remote/gateways/remote_efsnet_test.rb
- test/remote/gateways/remote_eway_test.rb
- test/remote/gateways/remote_exact_test.rb
- test/remote/gateways/remote_linkpoint_test.rb
- test/remote/gateways/remote_modern_payments_cim_test.rb
- test/remote/gateways/remote_modern_payments_test.rb
- test/remote/gateways/remote_moneris_test.rb
- test/remote/gateways/remote_net_registry_test.rb
- test/remote/gateways/remote_netbilling_test.rb
- test/remote/gateways/remote_pay_junction_test.rb
- test/remote/gateways/remote_pay_secure_test.rb
- test/remote/gateways/remote_payflow_express_test.rb
- test/remote/gateways/remote_payflow_test.rb
- test/remote/gateways/remote_payflow_uk_test.rb
- test/remote/gateways/remote_payment_express_test.rb
- test/remote/gateways/remote_paypal_express_test.rb
- test/remote/gateways/remote_paypal_test.rb
- test/remote/gateways/remote_plugnpay_test.rb
- test/remote/gateways/remote_protx_test.rb
- test/remote/gateways/remote_psigate_test.rb
- test/remote/gateways/remote_psl_card_test.rb
- test/remote/gateways/remote_quickpay_test.rb
- test/remote/gateways/remote_realex_test.rb
- test/remote/gateways/remote_sage_bankcard_test.rb
- test/remote/gateways/remote_sage_test.rb
- test/remote/gateways/remote_sage_virtual_check_test.rb
- test/remote/gateways/remote_secure_pay_au_test.rb
- test/remote/gateways/remote_secure_pay_tech_test.rb
- test/remote/gateways/remote_secure_pay_test.rb
- test/remote/gateways/remote_skipjack_test.rb
- test/remote/gateways/remote_trans_first_test.rb
- test/remote/gateways/remote_trust_commerce_test.rb
- test/remote/gateways/remote_usa_epay_test.rb
- test/remote/gateways/remote_verifi_test.rb
- test/remote/gateways/remote_viaklix_test.rb
- test/remote/gateways/remote_wirecard_test.rb
- test/remote/integrations
- test/remote/integrations/remote_gestpay_integration_test.rb
- test/remote/integrations/remote_paypal_integration_test.rb
- test/test_helper.rb
- test/unit
- test/unit/avs_result_test.rb
- test/unit/base_test.rb
- test/unit/check_test.rb
- test/unit/country_code_test.rb
- test/unit/country_test.rb
- test/unit/credit_card_formatting_test.rb
- test/unit/credit_card_methods_test.rb
- test/unit/credit_card_test.rb
- test/unit/cvv_result_test.rb
- test/unit/expiry_date_test.rb
- test/unit/gateways
- test/unit/gateways/authorize_net_cim_test.rb
- test/unit/gateways/authorize_net_test.rb
- test/unit/gateways/beanstream_interac_test.rb
- test/unit/gateways/beanstream_test.rb
- test/unit/gateways/bogus_test.rb
- test/unit/gateways/braintree_test.rb
- test/unit/gateways/card_stream_test.rb
- test/unit/gateways/cyber_source_test.rb
- test/unit/gateways/data_cash_test.rb
- test/unit/gateways/efsnet_test.rb
- test/unit/gateways/eway_test.rb
- test/unit/gateways/exact_test.rb
- test/unit/gateways/gateway_test.rb
- test/unit/gateways/linkpoint_test.rb
- test/unit/gateways/modern_payments_cim_test.rb
- test/unit/gateways/moneris_test.rb
- test/unit/gateways/net_registry_test.rb
- test/unit/gateways/netbilling_test.rb
- test/unit/gateways/pay_junction_test.rb
- test/unit/gateways/pay_secure_test.rb
- test/unit/gateways/payflow_express_test.rb
- test/unit/gateways/payflow_express_uk_test.rb
- test/unit/gateways/payflow_test.rb
- test/unit/gateways/payflow_uk_test.rb
- test/unit/gateways/payment_express_test.rb
- test/unit/gateways/paypal_express_test.rb
- test/unit/gateways/paypal_test.rb
- test/unit/gateways/plugnpay_test.rb
- test/unit/gateways/protx_test.rb
- test/unit/gateways/psigate_test.rb
- test/unit/gateways/psl_card_test.rb
- test/unit/gateways/quickpay_test.rb
- test/unit/gateways/realex_test.rb
- test/unit/gateways/sage_bankcard_test.rb
- test/unit/gateways/sage_virtual_check_test.rb
- test/unit/gateways/secure_pay_au_test.rb
- test/unit/gateways/secure_pay_tech_test.rb
- test/unit/gateways/secure_pay_test.rb
- test/unit/gateways/skip_jack_test.rb
- test/unit/gateways/trans_first_test.rb
- test/unit/gateways/trust_commerce_test.rb
- test/unit/gateways/usa_epay_test.rb
- test/unit/gateways/verifi_test.rb
- test/unit/gateways/viaklix_test.rb
- test/unit/gateways/wirecard_test.rb
- test/unit/generators
- test/unit/generators/test_gateway_generator.rb
- test/unit/generators/test_generator_helper.rb
- test/unit/generators/test_integration_generator.rb
- test/unit/integrations
- test/unit/integrations/action_view_helper_test.rb
- test/unit/integrations/bogus_module_test.rb
- test/unit/integrations/chronopay_module_test.rb
- test/unit/integrations/gestpay_module_test.rb
- test/unit/integrations/helpers
- test/unit/integrations/helpers/bogus_helper_test.rb
- test/unit/integrations/helpers/chronopay_helper_test.rb
- test/unit/integrations/helpers/gestpay_helper_test.rb
- test/unit/integrations/helpers/hi_trust_helper_test.rb
- test/unit/integrations/helpers/nochex_helper_test.rb
- test/unit/integrations/helpers/paypal_helper_test.rb
- test/unit/integrations/helpers/two_checkout_helper_test.rb
- test/unit/integrations/hi_trust_module_test.rb
- test/unit/integrations/nochex_module_test.rb
- test/unit/integrations/notifications
- test/unit/integrations/notifications/chronopay_notification_test.rb
- test/unit/integrations/notifications/gestpay_notification_test.rb
- test/unit/integrations/notifications/hi_trust_notification_test.rb
- test/unit/integrations/notifications/nochex_notification_test.rb
- test/unit/integrations/notifications/notification_test.rb
- test/unit/integrations/notifications/paypal_notification_test.rb
- test/unit/integrations/notifications/two_checkout_notification_test.rb
- test/unit/integrations/paypal_module_test.rb
- test/unit/integrations/returns
- test/unit/integrations/returns/chronopay_return_test.rb
- test/unit/integrations/returns/gestpay_return_test.rb
- test/unit/integrations/returns/hi_trust_return_test.rb
- test/unit/integrations/returns/nochex_return_test.rb
- test/unit/integrations/returns/paypal_return_test.rb
- test/unit/integrations/returns/return_test.rb
- test/unit/integrations/returns/two_checkout_return_test.rb
- test/unit/integrations/two_checkout_module_test.rb
- test/unit/post_data_test.rb
- test/unit/posts_data_test.rb
- test/unit/response_test.rb
- test/unit/utils_test.rb
- test/unit/validateable_test.rb
- script/destroy
- script/generate
- CHANGELOG
- CONTRIBUTERS
- gem-public_cert.pem
- init.rb
- lib
- MIT-LICENSE
- Rakefile
- README
- script
- test
homepage: http://activemerchant.org/
licenses: 
- "MIT"
post_install_message: 
rdoc_options: []

require_paths: 
- lib
required_ruby_version: !ruby/object:Gem::Requirement 
  requirements: 
  - - ">="
    - !ruby/object:Gem::Version 
      hash: 3
      segments: 
      - 0
      version: "0"
  version: 
required_rubygems_version: !ruby/object:Gem::Requirement 
  requirements: 
  - - ">="
    - !ruby/object:Gem::Version 
      hash: 3
      segments: 
      - 0
      version: "0"
  version: 
requirements: []

rubyforge_project: activemerchant
rubygems_version: 1.8.25
signing_key: 
specification_version: 2
summary: Framework and tools for dealing with credit card transactions.
test_files: []


