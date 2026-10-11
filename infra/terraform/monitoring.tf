# Cost and error alerts. Emails go to the subscription owner and to var.alert_emails.
# Set alert_emails in terraform.tfvars (gitignored), so no address lives in the repo.
# The owner alone isn't enough: a personal Microsoft account has no email in the directory.

locals {
  owner_role_id = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635" # built-in "Owner" role
}

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

resource "azurerm_monitor_action_group" "owners" {
  name                = "ag-${var.prefix}-owners"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = var.prefix
  tags                = local.tags

  arm_role_receiver {
    name                    = "subscription-owners"
    role_id                 = local.owner_role_id
    use_common_alert_schema = true
  }

  dynamic "email_receiver" {
    for_each = var.alert_emails
    content {
      name                    = "email-${email_receiver.key}"
      email_address           = email_receiver.value
      use_common_alert_schema = true
    }
  }
}

# Express apps don't report request metrics, so this watches the server's logs instead.
# It also catches failed background webhook scans, which never show up as an HTTP error.
resource "azurerm_monitor_scheduled_query_rules_alert_v2" "server_errors" {
  name                 = "${var.prefix}-server-errors"
  display_name         = "depscan-server errors"
  description          = "5xx responses, failed webhook scans or a panic in the depscan-server logs."
  resource_group_name  = azurerm_resource_group.main.name
  location             = azurerm_resource_group.main.location
  scopes               = [azurerm_log_analytics_workspace.main.id]
  evaluation_frequency = "PT15M"
  window_duration      = "PT15M"
  severity             = 2
  tags                 = local.tags

  criteria {
    query                   = <<-KQL
      ContainerAppConsoleLogs_CL
      | where ContainerAppName_s == "${azurerm_container_app.server.name}"
      | where Log_s matches regex @" (GET|POST|PUT|PATCH|DELETE|HEAD) \S+ 5\d\d "
          or (Log_s has "webhook:" and Log_s has "failed after")
          or Log_s has "panic"
    KQL
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
  }

  action {
    action_groups = [azurerm_monitor_action_group.owners.id]
  }
}
