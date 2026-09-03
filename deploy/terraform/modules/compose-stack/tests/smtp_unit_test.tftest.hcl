# Rendering tests for Zitadel's first-instance SMTP settings. Separate from
# render_unit_test.tftest.hcl only because that file is already at the
# repository's test-file length cap.
#
# Same properties as its sibling: `command = apply` is needed because the
# templates interpolate random_password, and the module's only resources ARE
# those in-memory random strings — nothing is created outside the test process.
#
# Run from the module directory: terraform init && terraform test

variables {
  exchange_hostname = "exchange.staging.example"
  broker_hostname   = "broker.staging.example"
  identity_hostname = "mcp.staging.example"
  zitadel_hostname  = "login.staging.example"

  default_tenant_domain = "demo.staging.example"

  exchange_image = "registry.example.com/group/proj/exchange:test"
  broker_image   = "registry.example.com/group/proj/broker:test"
  identity_image = "registry.example.com/group/proj/identity:test"

  acme_email = "ops@example.com"

  # Dummy key material — shape only, never used cryptographically.
  ed25519_private_pem     = "-----BEGIN PRIVATE KEY-----\ndGVzdA==\n-----END PRIVATE KEY-----\n"
  broker_relay_key_json   = "{\"kid\":\"broker.test.v1\"}"
  broker_identity_key_pem = "-----BEGIN ED25519 PRIVATE KEY-----\nZmFrZSBicm9rZXIgaWRlbnRpdHkgZml4dHVyZTogZXhhY3RseSBzaXh0eS1mb3VyIGJ5dGVzIGZvciB0ZnRlcw==\n-----END ED25519 PRIVATE KEY-----\n"
}

run "smtp_is_optional" {
  command = apply

  assert {
    # The prefix, not one full variable name: a partially rendered block would
    # still be caught, and callers that deploy without mail must get a compose
    # file with no mail settings at all.
    condition     = !strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_")
    error_message = "With no SMTP inputs the Zitadel service must carry no SMTP settings — a deployment without mail is a supported posture."
  }
}

run "smtp_renders_when_configured" {
  command = apply

  variables {
    smtp_host      = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user      = "AKIAEXAMPLEEXAMPLE"
    smtp_password  = "BEXAMPLEsmtppasswordEXAMPLE"
    smtp_from      = "noreply@demo.example"
    smtp_from_name = "RAMP Demo"
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_HOST: \"email-smtp.us-east-1.amazonaws.com:587\"")
    error_message = "The relay host must reach Zitadel exactly as configured, port included — Zitadel dials the string verbatim."
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_USER: \"AKIAEXAMPLEEXAMPLE\"")
    error_message = "The SMTP username must be rendered into the Zitadel service."
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_PASSWORD: \"BEXAMPLEsmtppasswordEXAMPLE\"")
    error_message = "The SMTP password must be rendered into the Zitadel service."
  }

  assert {
    # STARTTLS on the submission port. Rendered as a constant rather than an
    # input: no relay this bundle targets accepts credentials in the clear,
    # and a caller able to turn it off could send the password unencrypted.
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_TLS: \"true\"")
    error_message = "TLS must always be on: without it the SMTP password crosses the network in the clear."
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_FROM: \"noreply@demo.example\"")
    error_message = "The sender address must be rendered into the Zitadel service; SES rejects a send whose From is outside the verified identity."
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_FROMNAME: \"RAMP Demo\"")
    error_message = "The sender display name must be rendered into the Zitadel service."
  }
}

run "smtp_sender_name_defaults_when_absent" {
  command = apply

  variables {
    smtp_host     = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user     = "AKIAEXAMPLEEXAMPLE"
    smtp_password = "BEXAMPLEsmtppasswordEXAMPLE"
    smtp_from     = "noreply@demo.example"
  }

  assert {
    # Zitadel wants a non-empty display name. An omitted one must become a
    # neutral default, never an empty string.
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_FROMNAME: \"RAMP\"")
    error_message = "An omitted sender name must render the neutral default, not an empty display name."
  }
}

run "smtp_values_are_encoded" {
  command = apply

  variables {
    smtp_host = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user = "AKIAEXAMPLEEXAMPLE"
    # SES SMTP passwords are base64 and never contain these, but the encoding
    # is what makes that irrelevant: a relay whose password holds a quote or a
    # backslash must not be able to break the YAML document.
    smtp_password  = "pa\"ss\\word"
    smtp_from      = "noreply@demo.example"
    smtp_from_name = "RAMP \"Demo\""
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_SMTP_PASSWORD: \"pa\\\"ss\\\\word\"")
    error_message = "A password holding a quote or a backslash must be escaped into a JSON string literal, which is also a valid YAML scalar."
  }

  assert {
    condition     = strcontains(output.compose_yaml, "ZITADEL_DEFAULTINSTANCE_SMTPCONFIGURATION_FROMNAME: \"RAMP \\\"Demo\\\"\"")
    error_message = "A sender name holding a quote must be escaped the same way."
  }
}

run "smtp_host_without_port_is_rejected" {
  command = plan

  variables {
    smtp_host     = "email-smtp.us-east-1.amazonaws.com"
    smtp_user     = "AKIAEXAMPLEEXAMPLE"
    smtp_password = "BEXAMPLEsmtppasswordEXAMPLE"
    smtp_from     = "noreply@demo.example"
  }

  expect_failures = [
    var.smtp_host,
  ]
}

run "smtp_sender_with_a_line_break_is_rejected" {
  command = plan

  variables {
    smtp_host     = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user     = "AKIAEXAMPLEEXAMPLE"
    smtp_password = "BEXAMPLEsmtppasswordEXAMPLE"
    # A newline in the sender would inject a second mail header.
    smtp_from = "noreply@demo.example\nBcc: attacker@evil.example"
  }

  expect_failures = [
    var.smtp_from,
  ]
}

run "smtp_sender_name_with_a_line_break_is_rejected" {
  command = plan

  variables {
    smtp_host      = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user      = "AKIAEXAMPLEEXAMPLE"
    smtp_password  = "BEXAMPLEsmtppasswordEXAMPLE"
    smtp_from      = "noreply@demo.example"
    smtp_from_name = "RAMP\nBcc: attacker@evil.example"
  }

  expect_failures = [
    var.smtp_from_name,
  ]
}

# The four required inputs, each omitted in turn: every partial set must fail
# the plan rather than render a provider that only fails on its first send.

run "smtp_host_without_the_rest_is_rejected" {
  command = plan

  variables {
    smtp_host = "email-smtp.us-east-1.amazonaws.com:587"
  }

  expect_failures = [
    random_password.postgres,
  ]
}

run "smtp_without_user_is_rejected" {
  command = plan

  variables {
    smtp_host     = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_password = "BEXAMPLEsmtppasswordEXAMPLE"
    smtp_from     = "noreply@demo.example"
  }

  expect_failures = [
    random_password.postgres,
  ]
}

run "smtp_without_password_is_rejected" {
  command = plan

  variables {
    smtp_host = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user = "AKIAEXAMPLEEXAMPLE"
    smtp_from = "noreply@demo.example"
  }

  expect_failures = [
    random_password.postgres,
  ]
}

run "smtp_without_sender_is_rejected" {
  command = plan

  variables {
    smtp_host     = "email-smtp.us-east-1.amazonaws.com:587"
    smtp_user     = "AKIAEXAMPLEEXAMPLE"
    smtp_password = "BEXAMPLEsmtppasswordEXAMPLE"
  }

  expect_failures = [
    random_password.postgres,
  ]
}

run "smtp_credentials_without_a_host_are_rejected" {
  command = plan

  variables {
    smtp_user     = "AKIAEXAMPLEEXAMPLE"
    smtp_password = "BEXAMPLEsmtppasswordEXAMPLE"
    smtp_from     = "noreply@demo.example"
  }

  expect_failures = [
    random_password.postgres,
  ]
}
