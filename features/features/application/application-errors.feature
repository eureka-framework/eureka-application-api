Feature: Test common error on the application, not related to a feature
  As a "technical" client (mobile, service, script, backoffice)
  I need to be able to reach any endpoints or get appropriate error if not possible

  Scenario: Client requests an endpoint, with a bad http method, and gets an error response
     When I send the request to the endpoint "/" with http method "POST"
     Then I should get an error response
      And The response contains status code "405" and error code "901" in first error item

  Scenario: Client requests a non-existing endpoint, and gets an error response
     When I send the request to the endpoint "/non-existing-route" with http method "GET"
     Then I should get an error response
      And The response contains status code "404" and error code "900" in first error item

  Scenario: Client requests an endpoint more than times and reach the quota in elapsed time, and gets an error response
     When I send "6" requests to the endpoint "/auth/token/verify" with http method "POST"
     Then I should get an error response
      And The response contains status code "429" and error code "429" in first error item
