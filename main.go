package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

func main() {
    // Load the Rego policy file
	// 1 Policy decides severity for one rulset
    policyData, err := os.ReadFile("policies/policy-1.rego")
    if err != nil {
        log.Fatalf("Error reading policy file: %v", err)
    }

    // Create a new Rego instance with the policy
    r := rego.New(
        rego.Query("data.policies.severity"),
        rego.Module("policies.rego", string(policyData)),
    )

    // Read the input data from input.json
    data, err := os.ReadFile("input.json")
    if err != nil {
        log.Fatalf("Error reading input file: %v", err)
    }

    // Unmarshal the JSON data into a slice of maps
    var inputs []map[string]interface{}
    err = json.Unmarshal(data, &inputs)
    if err != nil {
        log.Fatalf("Error unmarshaling JSON data: %v", err)
    }

    // Prepare the query executor
    query, err := r.PrepareForEval(context.Background())
    if err != nil {
        log.Fatalf("Error preparing query: %v", err)
    }

    // Evaluate the policy for each input
    for _, input := range inputs {

        results, err := query.Eval(context.Background(), rego.EvalInput(input))
        if err != nil {
            log.Fatalf("Error evaluating policy: %v", err)
        }

        if len(results) > 0 {
            severity := results[0].Expressions[0].Value
            fmt.Printf("Input: %v \n Severity: %v\n", input, severity)
        } else {
            fmt.Printf("Input: %v \n Severity: NO MATCH\n", input)
        }
    }
}
