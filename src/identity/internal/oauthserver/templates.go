package oauthserver

import (
	"fmt"
	"html/template"
)

// consentTemplateName names the one page this server renders.
const consentTemplateName = "consent"

// defaultTemplates parses the built-in consent page. html/template auto-escapes
// every interpolation, so the client-supplied client name and the redirect URI it
// asks the code to be sent to are both rendered safely.
func defaultTemplates() (*template.Template, error) {
	tmpl, err := template.New(consentTemplateName).Parse(consentHTML)
	if err != nil {
		return nil, fmt.Errorf("oauthserver: parse consent template: %w", err)
	}
	return tmpl, nil
}

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
agent identity <span class="sub" id="agent-subdomain">{{.Subdomain}}</span>.</p>
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
