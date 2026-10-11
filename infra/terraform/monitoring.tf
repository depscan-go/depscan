# Budget emails. They go to the subscription owner and to var.alert_emails; set alert_emails in
# terraform.tfvars (gitignored), so no address lives in the repo. Error alerts are handled by the
# GitHub watchdog workflow instead: Azure doesn't deliver alert emails on this (free) subscription.

resource "azurerm_consumption_budget_subscription" "monthly" {
  name            = "${var.prefix}-monthly"
  subscription_id = "/subscriptions/${var.subscription_id}"
  amount          = var.monthly_budget
  time_grain      = "Monthly"

  time_period {
    start_date = var.budget_start
  }

  notification {
    threshold      = 50
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_roles  = ["Owner"]
    contact_emails = var.alert_emails
  }

  notification {
    threshold      = 100
    operator       = "GreaterThan"
    threshold_type = "Actual"
    contact_roles  = ["Owner"]
    contact_emails = var.alert_emails
  }

  # Warns before the money is gone, not after.
  notification {
    threshold      = 100
    operator       = "GreaterThan"
    threshold_type = "Forecasted"
    contact_roles  = ["Owner"]
    contact_emails = var.alert_emails
  }
}
