package xacml

import (
	"github.com/clbanning/mxj"
	"testing"
)

var requestString = `<?xml version="1.0" encoding="UTF-8"?>
<Request xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
  xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd">
  <Attributes Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject">
    <Attribute 
      IncludeInResult="false"
      AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id">
        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Carl</AttributeValue>
    </Attribute>
  </Attributes>
  <Attributes Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource">
    <Attribute 
      IncludeInResult="false"
      AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id">
        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">^/record.txt</AttributeValue>
    </Attribute>
  </Attributes>
  <Attributes Category="urn:oasis:names:tc:xacml:1.0:attribute-category:action">
    <Attribute 
      IncludeInResult="false"
      AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id">
        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue>
    </Attribute>
  </Attributes>
</Request>`

var policyString2 = `<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17" 
		xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
		xsi:schemaLocation="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17 http://docs.oasis-open.org/xacml/3.0/xacml-core-v3-schema-wd-17.xsd" 
		PolicyId="simple-policy" 
		Version="1.0" 
		RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
	<Description>Patient Policy</Description>
	<Target>
	  <AnyOf>
	    <AllOf>
		  <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
		    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
			  ^/record.txt</AttributeValue>
			<AttributeDesignator
			  MustBePresent="false"
			  Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
			  AttributeId="urn:oasis:names:tc:xacml:1.0:resource:resource-id" 
			  DataType="http://www.w3.org/2001/XMLSchema#string"/>
		  </Match>
		</AllOf>
	  </AnyOf>
	</Target>
	<Rule
	  RuleId="urn:oasis:names:tc:xacml:3.0:example:SimpleRule"
	  Effect="Permit">
	  <Description>
	  	Deny record access 
	  </Description>
	  <Target>
	    <AnyOf>
		  <AllOf>
		    <Match
			  MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
			  <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
			    Carl</AttributeValue>
			  <AttributeDesignator
			    MustBePresent="false"
				Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
				AttributeId="urn:oasis:names:tc:xacml:1.0:subject:subject-id"
				DataType="http://www.w3.org/2001/XMLSchema#string"/>
			</Match>
		    <Match
			  MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
		      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">
			    read</AttributeValue>
			  <AttributeDesignator
			    MustBePresent="false"
				Category="urn:oasis:names:tc:xacml:1.0:attribute-category:action"
				AttributeId="urn:oasis:names:tc:xacml:1.0:action:action-id"
				DataType="http://www.w3.org/2001/XMLSchema#string"/>
			</Match>
		  </AllOf>
		</AnyOf>
	  </Target>
	</Rule>
</Policy>`

func TestSimplePatientPolicy(t *testing.T) {
	mxj.IncludeTagSeqNum(true)
	responseXML, err := PolicyDecisionPoint(policyString2, requestString)
	if err != nil {
		t.Error("Test Policy: Error evaluating policy", err)
	}
	r, err := GetResultFromResponse(responseXML)
	if r != ResponsePermit {
		t.Errorf("Test Policy Result: %v - %v", r, err)
	}
}
