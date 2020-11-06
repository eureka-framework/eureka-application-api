Feature: Get new token
  As a "technical" client (mobile, service, script, backoffice)
  I need to be able to request an endpoint to get new authentication token (Json Web Token).

  @fixtureUserId02
  Scenario: Client requests a new token with valid credential, and gets a successful response
    Given I set request body field "email" with value "user_enabled@example.com"
      And I set request body field "password" with value "password02"
     When I send the request to the endpoint "/auth/token/get" with http method "POST"
     Then I should get a success response
      And I get a valid token

  Scenario: Client requests a new token with an empty or missing email, and gets an error response
    Given I set request body field "email" with empty value
      And I set request body field "password" with value "password"
     When I send the request to the endpoint "/auth/token/get" with http method "POST"
     Then I should get an error response
      And The response contains status code "400" and error code "1200" in first error item

  Scenario: Client requests a new token with an empty or missing password, and gets an error response
    Given I set request body field "email" with value "user_enabled@example.com"
      And I set request body field "password" with empty value
     When I send the request to the endpoint "/auth/token/get" with http method "POST"
     Then I should get an error response
     And The response contains status code "400" and error code "1201" in first error item

  @fixtureNoUserId00
  Scenario: Client requests a new token with an unknown email, and gets an error response
    Given I set request body field "email" with value "user_unknown@example.com"
      And I set request body field "password" with value "password"
     When I send the request to the endpoint "/auth/token/get" with http method "POST"
     Then I should get an error response
      And The response contains status code "401" and error code "1202" in first error item

  @fixtureUserId02
  Scenario: Client requests a new token with a wrong password, and gets an error response
    Given I set request body field "email" with value "user_enabled@example.com"
      And I set request body field "password" with value "any_bad_password"
     When I send the request to the endpoint "/auth/token/get" with http method "POST"
     Then I should get an error response
      And The response contains status code "401" and error code "1202" in first error item

  @fixtureUserId03
  Scenario: Client requests a new token ona disabled account, and gets an error response
    Given I set request body field "email" with value "user_disabled@example.com"
      And I set request body field "password" with value "password03"
     When I send the request to the endpoint "/auth/token/get" with http method "POST"
     Then I should get an error response
      And The response contains status code "403" and error code "1203" in first error item
