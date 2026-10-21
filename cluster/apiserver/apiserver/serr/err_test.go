package serr

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInternalWithErr(t *testing.T) {
	userCodes := map[codes.Code]bool{
		codes.InvalidArgument: true, codes.NotFound: true, codes.AlreadyExists: true,
		codes.PermissionDenied: true, codes.Unauthenticated: true, codes.FailedPrecondition: true,
		codes.OutOfRange: true, codes.ResourceExhausted: true, codes.Unimplemented: true,
	}
	for code := codes.OK; code <= codes.Unauthenticated; code++ {
		if code == codes.OK {
			continue
		}
		assert.Equal(t, userCodes[code], isUserInduced(code))
		err := status.Error(code, "sensitive backend detail")
		for _, input := range []error{err, fmt.Errorf("wrapped: %w", err)} {
			got := InternalWithErr(input)
			if userCodes[code] {
				assert.Equal(t, code, status.Code(got))
				assert.Equal(t, "sensitive backend detail", status.Convert(got).Message())
			} else {
				assert.Equal(t, codes.Internal, status.Code(got))
				assert.Equal(t, "Internal error", status.Convert(got).Message())
			}
		}
	}
	assert.False(t, isUserInduced(codes.Code(1000)))
	assert.Equal(t, "Internal error", status.Convert(InternalWithErr(fmt.Errorf("password=secret"))).Message())
}

func TestErrors(t *testing.T) {
	assert.Equal(t, codes.InvalidArgument, status.Code(InvalidArg("invalid %s", "name")))
	assert.Equal(t, codes.InvalidArgument, status.Code(InvalidArgWithErr(fmt.Errorf("invalid"))))
	assert.Equal(t, codes.NotFound, status.Code(NotFound("missing %s", "resource")))
	assert.Equal(t, codes.PermissionDenied, status.Code(Unauthorized("denied %s", "resource")))
	assert.Equal(t, codes.Unauthenticated, status.Code(UnauthenticatedWithErr(fmt.Errorf("secret"))))
	assert.Equal(t, "Unauthenticated User", status.Convert(UnauthenticatedWithErr(fmt.Errorf("secret"))).Message())
	assert.Equal(t, "Internal error", status.Convert(Internal("secret %s", "value")).Message())
	for _, err := range []error{fmt.Errorf("secret"), status.Error(codes.Unavailable, "secret")} {
		assert.Equal(t, codes.Internal, status.Code(K8sInternal(err)))
		assert.Equal(t, codes.Internal, status.Code(K8sNotFoundOrInternal(err, "missing %s", "resource")))
		assert.Equal(t, codes.Internal, status.Code(K8sNotFoundOrInternalWithErr(err)))
	}
	err := status.Error(codes.NotFound, "missing")
	assert.Equal(t, codes.NotFound, status.Code(K8sNotFoundOrInternal(err, "missing %s", "resource")))
	assert.Equal(t, "missing resource", status.Convert(K8sNotFoundOrInternal(err, "missing %s", "resource")).Message())
	assert.Same(t, err, K8sNotFoundOrInternalWithErr(err))
}

func TestK8sInternalHidesDetails(t *testing.T) {
	t.Setenv("OCTELIUM_DEV", "false")
	t.Setenv("OCTELIUM_PRODUCTION", "true")
	err := K8sInternal(fmt.Errorf("password=secret"))
	assert.Equal(t, codes.Internal, status.Code(err))
	assert.Equal(t, "Internal error", status.Convert(err).Message())
}
