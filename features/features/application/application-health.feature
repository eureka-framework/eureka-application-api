Feature: Monitor Application Health
  As a "technical" client (mobile, service, script, backoffice)
  I need to be able to request some endpoints to monitor application health.

  Scenario: Client requests for liveness of the application, and the application is up, and gets a successful response
     When I send the request to the endpoint "/liveness" with http method "GET"
     Then I should get a success response
      And The response contains a value string "ok"

  Scenario: Client requests for readiness of the application, and all tiers services are up, and gets a successful response
     When I send the request to the endpoint "/readiness" with http method "GET"
     Then I should get a success response
      But The response contains a value string "ok"