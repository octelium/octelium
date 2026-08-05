// Copyright Octelium Labs, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package octelium

import (
	"errors"
	"fmt"
)

var (
	ErrClientClosed                 = errors.New("octelium: client is closed")
	ErrNoCredentials                = errors.New("octelium: no credentials were provided")
	ErrNoManagedSession             = errors.New("octelium: client does not own a Cluster Session")
	ErrSessionExpired               = errors.New("octelium: Session expired and the configured authenticator cannot be reused")
	ErrHTTPDestinationNotAuthorized = errors.New("octelium: HTTP destination is not authorized to receive the access token")
)

// AuthenticationError reports a failure to create a Cluster Session.
type AuthenticationError struct {
	Err error
}

func (e *AuthenticationError) Error() string {
	if e == nil || e.Err == nil {
		return "octelium: could not authenticate"
	}
	return "octelium: could not authenticate: " + e.Err.Error()
}

func (e *AuthenticationError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// RefreshError reports a failure to refresh an existing Cluster Session. The
// Client preserves the current Session state so a later call can retry.
type RefreshError struct {
	Err error
}

func (e *RefreshError) Error() string {
	if e == nil || e.Err == nil {
		return "octelium: could not refresh the Session"
	}
	return "octelium: could not refresh the Session: " + e.Err.Error()
}

func (e *RefreshError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// HTTPAuthorizationError reports that the SDK refused to attach a bearer token
// to an HTTP destination.
type HTTPAuthorizationError struct {
	URL string
	Err error
}

func (e *HTTPAuthorizationError) Error() string {
	if e == nil {
		return ErrHTTPDestinationNotAuthorized.Error()
	}
	if e.URL == "" {
		return fmt.Sprintf("%s: %v", ErrHTTPDestinationNotAuthorized, e.Err)
	}
	return fmt.Sprintf("%s: %s: %v", ErrHTTPDestinationNotAuthorized, e.URL, e.Err)
}

func (e *HTTPAuthorizationError) Unwrap() error {
	return ErrHTTPDestinationNotAuthorized
}
