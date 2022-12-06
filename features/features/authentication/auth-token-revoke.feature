Feature: Revoke a token
  In order to logout
  As a "technical" client (mobile, service, script, backoffice)
  I need to be able to revoke my current token


  @mockUserId02
  Scenario: Client requests to revoke the user token, and gets a successful response
    Given I set request header registered token "valid" for user "2"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get a success response
      And The response contains a value string "ok"

  @mockUserId02
  Scenario: Client requests to revoke the user token, and gets a successful response
    Given I set request cookie registered token "valid" for user "2"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get a success response
      And The response contains a value string "ok"
