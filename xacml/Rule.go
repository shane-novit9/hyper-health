package xacml

/*
A rule is the most elementary unit of policy.  It may exist in isolation only within one of the major actors of the XACML domain.
In order to exchange rules between major actors, they must be encapsulated in a policy.  A rule can be evaluated on the basis of
its contents.  The main components of a rule are:

·         a target;

·         an effect,

·         a condition,

·         obligation epxressions, and

·         advice expressions
*/

type Rule struct {
	rule map[string]interface{}
}

func (rule Rule) Evaluate(request Request) Response {
	ruleBody := rule.rule
	response := Response{make(map[string]interface{})}

	//Evaluate target
	targetResponse := evaluateTargetBody(ruleBody["Target"], request)
	if targetResponse == targetNoMatch {
		response.AddResult(ResponseNotApplicable, "Rule Target didn't match")
		return response
	}
	if targetResponse == targetIndeterminate {
		response.AddResult(ResponseIndeterminate, "Error evaluating target")
		return response
	}

	//Evaluate condition
	conditionResponse := evaluateConditionBody(ruleBody["Condition"], request)
	switch conditionResponse {
	case ConditionTrue:
		effect, _ := rule.rule["-Effect"].(string)
		response.AddResult(effect, "")
		return response
	case ConditionFalse:
		response.AddResult(ResponseNotApplicable, "Condition returned false")
		return response
	case ConditionIndeterminate:
		response.AddResult(ResponseIndeterminate, "Error evaluating Condition")
		return response
	}

	response.AddResult(ResponseIndeterminate, "No other case caught")
	return response
}
