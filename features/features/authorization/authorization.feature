Feature: Test authorization errors on the application, not related to a feature
  As a "technical" client (mobile, service, script, backoffice)
  I need to be able to reach any endpoints or get appropriate error if authorization failed (about token or ownership)

  Scenario: Client requests an authenticated endpoint without auth token, and gets an error response
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get an error response
      And The response contains status code "400" and error code "1060" in first error item

  @mockUserId02
  Scenario: Client requests an authenticated endpoint with an expired auth token, and gets an error response
    Given I set request header token "expired" for user "2"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get an error response
      And The response contains status code "401" and error code "1050" in first error item

  @mockUserId02
  Scenario: Client requests an authenticated endpoint with an invalid auth token, and gets an error response
    Given I set request header token "invalid" for user "2"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get an error response
      And The response contains status code "400" and error code "1051" in first error item

  @mockUserId03
  Scenario: Client requests an authenticated endpoint with a valid auth token but for a disabled account, and gets an error response
    Given I set request header token "valid" for user "3"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get an error response
      And The response contains status code "403" and error code "1052" in first error item

  @mockUserId02
  Scenario: Client requests an authenticated endpoint with a valid auth token but the token is unknown (or revoked), and gets an error response
    Given I set request header token "valid" for user "2"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get an error response
      And The response contains status code "401" and error code "1053" in first error item

  @mockNoUserId00
  Scenario: Client requests an authenticated endpoint with a valid auth token but the user is unknown, and gets an error response
    Given I set request header token "valid" for user "0"
     When I send the request to the endpoint "/auth/token/revoke" with http method "POST"
     Then I should get an error response
      And The response contains status code "401" and error code "1054" in first error item
