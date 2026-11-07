package ldap

import (
	"errors"
	"strings"
	"testing"
)

// resultCodeCases enumerates every declared result code with its RFC name and sentinel. |
// resultCodeCases 列出每个已声明结果码及其 RFC 名称与哨兵。
var resultCodeCases = []struct {
	code     ResultCode
	name     string
	sentinel error
}{
	{ResultSuccess, "success", nil},
	{ResultOperationsError, "operationsError", ErrOperationsError},
	{ResultProtocolError, "protocolError", ErrProtocolError},
	{ResultTimeLimitExceeded, "timeLimitExceeded", ErrTimeLimitExceeded},
	{ResultSizeLimitExceeded, "sizeLimitExceeded", ErrSizeLimitExceeded},
	{ResultCompareFalse, "compareFalse", ErrCompareFalse},
	{ResultCompareTrue, "compareTrue", ErrCompareTrue},
	{ResultAuthMethodNotSupported, "authMethodNotSupported", ErrAuthMethodNotSupported},
	{ResultStrongerAuthRequired, "strongerAuthRequired", ErrStrongAuthRequired},
	{ResultReferral, "referral", ErrReferral},
	{ResultAdminLimitExceeded, "adminLimitExceeded", ErrAdminLimitExceeded},
	{ResultUnavailableCriticalExtension, "unavailableCriticalExtension", ErrUnavailableCriticalExtension},
	{ResultConfidentialityRequired, "confidentialityRequired", ErrConfidentialityRequired},
	{ResultSASLBindInProgress, "saslBindInProgress", ErrSASLBindInProgress},
	{ResultNoSuchAttribute, "noSuchAttribute", ErrNoSuchAttribute},
	{ResultUndefinedAttributeType, "undefinedAttributeType", ErrUndefinedAttributeType},
	{ResultConstraintViolation, "constraintViolation", ErrConstraintViolation},
	{ResultAttributeOrValueExists, "attributeOrValueExists", ErrAttributeOrValueExists},
	{ResultInvalidAttributeSyntax, "invalidAttributeSyntax", ErrInvalidAttributeSyntax},
	{ResultNoSuchObject, "noSuchObject", ErrNoSuchObject},
	{ResultAliasProblem, "aliasProblem", ErrAliasProblem},
	{ResultInvalidDNSyntax, "invalidDNSyntax", ErrInvalidDNSyntax},
	{ResultAliasDereferencingProblem, "aliasDereferencingProblem", ErrAliasDereferencingProblem},
	{ResultInappropriateAuthentication, "inappropriateAuthentication", ErrInappropriateAuthentication},
	{ResultInvalidCredentials, "invalidCredentials", ErrInvalidCredentials},
	{ResultInsufficientAccess, "insufficientAccessRights", ErrInsufficientAccess},
	{ResultBusy, "busy", ErrBusy},
	{ResultUnavailable, "unavailable", ErrUnavailable},
	{ResultUnwillingToPerform, "unwillingToPerform", ErrUnwillingToPerform},
	{ResultLoopDetect, "loopDetect", ErrLoopDetect},
	{ResultSortControlMissing, "sortControlMissing", ErrSortControlMissing},
	{ResultOffsetRangeError, "offsetRangeError", ErrOffsetRangeError},
	{ResultNamingViolation, "namingViolation", ErrNamingViolation},
	{ResultObjectClassViolation, "objectClassViolation", ErrObjectClassViolation},
	{ResultNotAllowedOnNonLeaf, "notAllowedOnNonLeaf", ErrNotAllowedOnNonLeaf},
	{ResultNotAllowedOnRDN, "notAllowedOnRDN", ErrNotAllowedOnRDN},
	{ResultEntryAlreadyExists, "entryAlreadyExists", ErrEntryAlreadyExists},
	{ResultObjectClassModsProhibited, "objectClassModsProhibited", ErrObjectClassModsProhibited},
	{ResultResultsTooLarge, "resultsTooLarge", ErrResultsTooLarge},
	{ResultAffectsMultipleDSAs, "affectsMultipleDSAs", ErrAffectsMultipleDSAs},
	{ResultVirtualListViewError, "virtualListViewError", ErrVirtualListViewError},
	{ResultOther, "other", ErrOther},
	{ResultCanceled, "canceled", ErrCanceled},
	{ResultNoSuchOperation, "noSuchOperation", ErrNoSuchOperation},
	{ResultTooLate, "tooLate", ErrTooLate},
	{ResultCannotCancel, "cannotCancel", ErrCannotCancel},
	{ResultAssertionFailed, "assertionFailed", ErrAssertionFailed},
}

// TestResultCodeNamesAndSentinels verifies every result code maps to its RFC name and sentinel. |
// TestResultCodeNamesAndSentinels 校验每个结果码映射到 RFC 名称与哨兵。
func TestResultCodeNamesAndSentinels(t *testing.T) {
	for _, testCase := range resultCodeCases {
		if got := testCase.code.String(); got != testCase.name {
			t.Fatalf("ResultCode(%d).String() = %q, want %q", testCase.code, got, testCase.name)
		}
		if got := sentinelForCode(testCase.code); got != testCase.sentinel {
			t.Fatalf("sentinelForCode(%d) = %v, want %v", testCase.code, got, testCase.sentinel)
		}
		result := LDAPResult{Code: testCase.code, MatchedDN: "dc=example", DiagnosticMessage: "diagnostic"}
		failureError := newResultError("search", result)
		if testCase.sentinel == nil {
			if failureError != nil {
				t.Fatalf("success produced error %v", failureError)
			}
			continue
		}
		failure, ok := failureError.(*Error)
		if !ok || !errors.Is(failure, testCase.sentinel) {
			t.Fatalf("newResultError(%d) = %v, want sentinel %v", testCase.code, failureError, testCase.sentinel)
		}
		if failure.Operation != "search" || failure.MatchedDN != "dc=example" ||
			failure.DiagnosticMessage != "diagnostic" || len(failure.Referrals) != 0 {
			t.Fatalf("newResultError fields = %+v", failure)
		}
	}
	if got := ResultCode(999).String(); got != "unknown" {
		t.Fatalf("unknown result name = %q", got)
	}
	if got := sentinelForCode(ResultCode(999)); got != ErrOther {
		t.Fatalf("unknown result sentinel = %v", got)
	}
}

// TestErrorTextAndMatching verifies safe formatting, truncation and errors.Is semantics. |
// TestErrorTextAndMatching 校验安全格式化、截断与 errors.Is 语义。
func TestErrorTextAndMatching(t *testing.T) {
	var nilError *Error
	if nilError.Error() != "<nil>" || nilError.Unwrap() != nil || nilError.Is(nil) {
		t.Fatalf("nil error behavior")
	}
	minimal := &Error{Code: ResultInvalidCredentials}
	if got := minimal.Error(); got != "ldap: invalidCredentials (49)" {
		t.Fatalf("minimal text = %q", got)
	}
	full := &Error{
		Code:              ResultNoSuchObject,
		MatchedDN:         "dc=example,dc=com",
		DiagnosticMessage: "entry missing",
		Operation:         "search",
		Referrals:         []string{"ldap://other"},
	}
	if got := full.Error(); got != "ldap search: noSuchObject (32), matched DN dc=example,dc=com: entry missing" {
		t.Fatalf("full text = %q", got)
	}
	long := &Error{Code: ResultOther, DiagnosticMessage: strings.Repeat("x", 600)}
	text := long.Error()
	if !strings.HasSuffix(text, "...") || !strings.Contains(text, strings.Repeat("x", 512)) ||
		strings.Contains(text, strings.Repeat("x", 513)) {
		t.Fatalf("long diagnostic not capped: len %d", len(text))
	}
	if !errors.Is(full, &Error{Code: ResultNoSuchObject}) {
		t.Fatalf("same code does not match")
	}
	if errors.Is(full, &Error{Code: ResultOther}) {
		t.Fatalf("different code matched")
	}
	if !errors.Is(full, ErrNoSuchObject) {
		t.Fatalf("sentinel does not match")
	}
	if errors.Is(full, nil) || errors.Is((*Error)(nil), ErrNoSuchObject) {
		t.Fatalf("nil matching is true")
	}
}
