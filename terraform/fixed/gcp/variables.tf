variable "project_number" {
  description = "Number (not the ID) of the project, used to build the Cloud Storage service agent address. The default is a placeholder so the code can be planned offline."
  type        = string
  default     = "123456789012"
}
