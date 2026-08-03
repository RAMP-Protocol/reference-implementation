package oauthserver

import (
	"fmt"
	"html/template"
)

// Template names within the parsed set.
const (
	formTemplateName    = "form"
	consentTemplateName = "consent"
)

// defaultTemplates parses the built-in registration and consent pages.
// html/template auto-escapes every interpolation, so prior form values, error
// messages, and the client-supplied client name are all rendered safely.
func defaultTemplates() (*template.Template, error) {
	tmpl, err := template.New(formTemplateName).Parse(registrationFormHTML)
	if err != nil {
		return nil, fmt.Errorf("oauthserver: parse form template: %w", err)
	}
	if _, err := tmpl.New(consentTemplateName).Parse(consentHTML); err != nil {
		return nil, fmt.Errorf("oauthserver: parse consent template: %w", err)
	}
	return tmpl, nil
}

// registrationFormHTML is the mandatory-gate form. It re-renders with prior values
// and per-field errors when validation fails, so a developer fixes every problem in
// one pass. The field names match signup.Field* and the /form POST reads them back.
const registrationFormHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Complete your RAMP registration</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  label { display: block; margin: 1.1rem 0 0.3rem; font-weight: 600; }
  input, textarea { width: 100%; padding: 0.5rem; font: inherit; box-sizing: border-box; }
  .error { color: #b00020; display: block; margin-top: 0.3rem; font-size: 0.9rem; }
  .sub { font-family: ui-monospace, monospace; }
  button { margin-top: 1.5rem; padding: 0.6rem 1.2rem; font: inherit; cursor: pointer; }
  .intro { color: #444; }
</style>
</head>
<body>
<main>
<h1>Complete your registration</h1>
<p class="intro">Your agent identity <span class="sub">{{.Subdomain}}</span> is provisioned.
Before it can be used, the licensing details below are required. All three fields are mandatory.</p>
<form method="post" action="` + FormPath + `" novalidate>
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <label for="legal_entity">Legal entity</label>
  <input id="legal_entity" name="legal_entity" value="{{.Values.LegalEntity}}" autocomplete="organization">
  {{with index .Errors "legal_entity"}}<span class="error">{{.}}</span>{{end}}

  <label for="address">Address</label>
  <textarea id="address" name="address" rows="3">{{.Values.Address}}</textarea>
  {{with index .Errors "address"}}<span class="error">{{.}}</span>{{end}}

  <label for="jurisdiction_country">Jurisdiction (ISO 3166-1 alpha-2 country code)</label>
  <input id="jurisdiction_country" name="jurisdiction_country" value="{{.Values.JurisdictionCountry}}" maxlength="2">
  {{with index .Errors "jurisdiction_country"}}<span class="error">{{.}}</span>{{end}}

  <button type="submit">Complete registration</button>
</form>
</main>
</body>
</html>
`

// consentHTML is the resource-owner authorization screen. It names the requesting
// client (auto-escaped — the name comes from client-controlled Dynamic Client
// Registration), shows the minted subdomain and the exact redirect the code would be
// sent to, and warns that the client is self-registered and unverified, so a phished
// developer can recognise a request they did not start and Deny it.
const consentHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access — RAMP</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 34rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.4rem; }
  .intro { color: #444; }
  .sub { font-family: ui-monospace, monospace; word-break: break-all; }
  .warn { color: #8a5300; background: #fff4e0; border: 1px solid #f0c675; padding: 0.6rem 0.8rem; border-radius: 4px; }
  .actions { margin-top: 1.5rem; display: flex; gap: 0.8rem; }
  button { padding: 0.6rem 1.2rem; font: inherit; cursor: pointer; }
  button.approve { font-weight: 600; }
</style>
</head>
<body>
<main>
<h1>Authorize access</h1>
<p class="intro">The application <strong>{{.ClientName}}</strong> is requesting access to your
agent identity <span class="sub">{{.Subdomain}}</span>.</p>
<p class="intro">If you approve, an authorization code will be sent to:<br>
<span class="sub">{{.RedirectURI}}</span></p>
<p class="warn">Only approve if you started this sign-in. This application registered itself
and its name is not verified.</p>
<form method="post" action="` + ConsentPath + `" novalidate>
  <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
  <div class="actions">
    <button class="approve" type="submit" name="decision" value="approve">Approve</button>
    <button type="submit" name="decision" value="deny">Deny</button>
  </div>
</form>
</main>
</body>
</html>
`
