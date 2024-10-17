package policies

import rego.v1

severity := "CRITICAL" if {
	# Mandatory Features
	input.is_high_volume_select_hour == 1
	input.is_high_volume_select_day == 1
	input.outlier_max_score_summary_hour >= 0.9

	# Key Characteristics
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.9
	input.sensitive_obj_day >= 0.8
} else := "HIGH" if {
	# Mandatory Features
	input.is_high_volume_select_hour == 1
	input.is_high_volume_select_day == 1
	input.outlier_max_score_summary_hour >= 0.8
	input.outlier_max_score_summary_hour < 0.9

	# Key Characteristics
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.8
	input.sensitive_obj_hour < 0.9
	input.sensitive_obj_day >= 0.6
	input.sensitive_obj_day < 0.8
} else := "MEDIUM" if {
	# Mandatory Features
	input.is_high_volume_select_hour == 1
	input.is_high_volume_select_day == 1
	# or
	input.outlier_max_score_summary_hour >= 0.6
	input.outlier_max_score_summary_hour < 0.8

	# Key Characteristics
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.6
	input.sensitive_obj_hour < 0.8
	input.sensitive_obj_day >= 0.3
	input.sensitive_obj_day < 0.6
} else := "LOW" if {
	# Mandatory Features
	input.is_high_volume_select_hour == 1
	input.is_high_volume_select_day == 1
	# or
	input.outlier_max_score_summary_hour >= 0.3
	input.outlier_max_score_summary_hour < 0.6

	# Key Characteristics
	input.is_admin_hour == 1
	input.sensitive_obj_hour >= 0.3
	input.sensitive_obj_hour < 0.6
	input.sensitive_obj_day < 0.3
}
