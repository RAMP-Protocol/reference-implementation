# Outbound mail for Zitadel, via Amazon SES.
#
# Developer self-registration sends a confirmation code, so without a mail
# provider the sign-up flow cannot complete. Zitadel reads its provider
# settings only when it first creates its instance, which means these values
# reach it through the compose bundle in the VM's cloud-init user data — and
# changing any of them replaces the VM.
#
# Everything here is created in us-east-1 regardless of where the VM runs.
# SES sandbox status, the SMTP endpoint, the DKIM CNAME targets, and the
# derived SMTP password are all per-region: moving SES to another region means
# re-deriving all four together, not editing the hostname alone.

locals {
  # host:port, dialled verbatim by Zitadel. 587 is the submission port, which
  # the module's rendering pairs with STARTTLS.
  zitadel_smtp_host = "email-smtp.us-east-1.amazonaws.com:587"

  # Must sit under the verified identity below, and must match the IAM policy
  # condition exactly — SES refuses the send otherwise.
  zitadel_smtp_from      = "noreply@${var.domain}"
  zitadel_smtp_from_name = "RAMP Demo"
}

# Domain identity rather than a single address: it lets the deployment send as
# any address under the domain later without a second verification round, and
# it is what Easy DKIM signs for.
resource "aws_sesv2_email_identity" "zitadel" {
  provider       = aws.us_east_1
  email_identity = var.domain
}

# Easy DKIM: SES generates three key pairs and publishes the public halves
# through CNAMEs that point back into its own zone. Sending stays unverified
# until all three resolve.
#
# The zone is shared, so this adds three records and touches nothing else.
# Confirm on the plan that no CNAME here already exists under different
# management before applying.
resource "aws_route53_record" "zitadel_ses_dkim" {
  count = 3

  zone_id = var.route53_zone_id
  name    = "${aws_sesv2_email_identity.zitadel.dkim_signing_attributes[0].tokens[count.index]}._domainkey"
  type    = "CNAME"
  ttl     = 300
  records = ["${aws_sesv2_email_identity.zitadel.dkim_signing_attributes[0].tokens[count.index]}.dkim.amazonses.com"]
}

# SES SMTP credentials are an IAM user's access key: the key id is the SMTP
# username, and the SMTP password is derived from the secret key with a
# region-specific step (ses_smtp_password_v4 below). A user of its own keeps
# the credential's blast radius to sending mail.
resource "aws_iam_user" "zitadel_smtp" {
  provider = aws.us_east_1
  name     = "${var.name_prefix}-zitadel-smtp"
}

resource "aws_iam_user_policy" "zitadel_smtp" {
  provider = aws.us_east_1
  user     = aws_iam_user.zitadel_smtp.name

  # Deliberately narrow, and NOT AmazonSESFullAccess: this credential travels
  # in the VM's user data, so it must be able to do exactly one thing. The
  # SMTP interface calls SendRawEmail; the condition pins the sender so a
  # leaked credential cannot send as anything but the notification address.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ses:SendRawEmail"]
      Resource = aws_sesv2_email_identity.zitadel.arn
      Condition = {
        StringEquals = {
          "ses:FromAddress" = local.zitadel_smtp_from
        }
      }
    }]
  })
}

resource "aws_iam_access_key" "zitadel_smtp" {
  provider = aws.us_east_1
  user     = aws_iam_user.zitadel_smtp.name
}
