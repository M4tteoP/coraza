// Copyright 2022 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"github.com/corazawaf/coraza/v3/testing/profile"
)

var _ = profile.RegisterProfile(profile.Profile{
	Meta: profile.Meta{
		Author:      "m4tteoP",
		Description: "Test if a rule is not triggered twice",
		Enabled:     true,
		Name:        "rule.yaml",
	},
	Tests: []profile.Test{
		{
			Title: "rule",
			Stages: []profile.Stage{
				{
					Stage: profile.SubStage{
						Input: profile.StageInput{
							URI:    "/api?var=api",
							Method: "POST",
							Data:   "api",
							Headers: map[string]string{
								"Host":           "localhost",
								"Content-Type":   "application/x-www-form-urlencoded",
								"content-length": "3",
							},
						},
						Output: profile.ExpectedOutput{
							TriggeredRules:    []int{2},
							NonTriggeredRules: []int{3},
						},
					},
				},
			},
		},
	},
	// Rule 1 permits also to verify that MultiPhase evaluation properly skips a rule that has been already triggered.
	// It happens because REQUEST_URI and ARGS_GET are triggered at the inferred phase 1, while REQUEST_BODY is triggered
	// at phase 2. The latter should be skept (rule already matched at phase 1)
	//
	Rules: `
SecRequestBodyAccess On
SecRule REQUEST_URI|REQUEST_BODY "api" "id:1, phase:2, pass, log,setvar:'TX.anomaly_score=+1'"
SecRule TX:anomaly_score "@eq 1" "id:2,phase:2,log"
SecRule TX:anomaly_score "@gt 1" "id:3,phase:2,log"
`,
})
