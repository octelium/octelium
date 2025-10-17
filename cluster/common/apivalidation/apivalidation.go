/*
 * Copyright Octelium Labs, LLC. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3,
 * as published by the Free Software Foundation of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package apivalidation

import (
	"context"
	"net"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/asaskevich/govalidator"
	ua "github.com/mileusna/useragent"
	"github.com/octelium/octelium/apis/main/metav1"
	"github.com/octelium/octelium/cluster/apiserver/apiserver/serr"
	"github.com/octelium/octelium/cluster/common/grpcutils"
	"github.com/octelium/octelium/pkg/apiutils/umetav1"
	"github.com/octelium/octelium/pkg/common/pbutils"
	"github.com/octelium/octelium/pkg/common/rgx"
	"github.com/pkg/errors"
)

type ValidateMetadataOpts struct {
	RequireName bool
	RequireUID  bool
	ParentsMust uint64
	ParentsMax  uint64
}

func ValidateMetadata(m *metav1.Metadata, opts *ValidateMetadataOpts) error {
	if err := doValidateMetadata(m, opts); err != nil {
		return grpcutils.InvalidArgWithErr(err)
	}
	return nil
}

var rgxDoubleHyphen = regexp.MustCompile(`^[^-]+(?:-[^-]+)*$`)

func ValidateName(arg string, parentsMust uint64, parentsMax uint64) error {
	return validateName(arg, parentsMust, parentsMax)
}

func validateName(arg string, parentsMust uint64, parentsMax uint64) error {
	if parentsMust != 0 {
		args := strings.Split(arg, ".")
		if len(args) != int(parentsMust)+1 {
			return errors.Errorf("Invalid name: %s", arg)
		}

		for _, arg := range args {
			if !rgx.NameMain.MatchString(arg) {
				return errors.Errorf("Invalid name: %s", arg)
			}
		}
	} else if parentsMax != 0 {
		args := strings.Split(arg, ".")
		if len(args) > int(parentsMax)+1 {
			return errors.Errorf("Invalid name: %s", arg)
		}

		for _, arg := range args {
			if !rgx.NameMain.MatchString(arg) {
				return errors.Errorf("Invalid name: %s", arg)
			}
		}
	} else {
		if !rgx.NameMain.MatchString(arg) {
			return errors.Errorf("Invalid name: %s", arg)
		}
	}

	if !rgxDoubleHyphen.MatchString(arg) {
		return errors.Errorf("Invalid name: %s", arg)
	}

	if len(arg) > 128 {
		return errors.Errorf("Too long name: %s", arg)
	}

	return nil
}

func doValidateMetadata(m *metav1.Metadata, opts *ValidateMetadataOpts) error {
	if opts == nil {
		opts = &ValidateMetadataOpts{}
	}

	if m == nil {
		return errors.Errorf("You must provide Metadata for the Resource")
	}

	if opts.RequireName && m.Name == "" {
		return errors.Errorf("You must provide a name for the Resource")
	}

	if m.Name != "" {
		if err := validateName(m.Name, opts.ParentsMust, opts.ParentsMax); err != nil {
			return err
		}
	}

	if opts.RequireUID && m.Uid == "" {
		return errors.Errorf("UID is required")
	}

	if m.Uid != "" && !govalidator.IsUUIDv4(m.Uid) {
		return errors.Errorf("Invalid UID")
	}

	if len(m.DisplayName) > 100 {
		return errors.Errorf("Display name is too long is too long")
	}

	if len(m.Description) > 1024 {
		return errors.Errorf("Description is too long")
	}

	if m.Labels != nil {
		if len(m.Labels) > 64 {
			return errors.Errorf("Labels map is too large")
		}
	}

	for k, v := range m.Labels {
		if !rgx.NameMain.MatchString(k) {
			return errors.Errorf("Invalid label key: %s", k)
		}

		if !rgx.LabelVal.MatchString(v) {
			return errors.Errorf("Invalid label value: %s", k)
		}
	}

	if m.Annotations != nil {
		if len(m.Annotations) > 64 {
			return errors.Errorf("Annotations map is too large")
		}
	}

	for k, v := range m.Annotations {
		if !rgx.NameMain.MatchString(k) {
			return errors.Errorf("Invalid annotation key: %s", k)
		}

		if len(v) > 63 {
			return errors.Errorf("annotation value of %s is too long", k)
		}
	}

	if m.Tags != nil {
		if len(m.Tags) > 64 {
			return errors.Errorf("Too many tags")
		}

		if len(m.Tags) > 0 {
			for _, tag := range m.Tags {
				if !rgx.NameMain.MatchString(tag) {
					return errors.Errorf("Invalid tag: %s", tag)
				}
			}

			tagsClone := slices.Clone(m.Tags)
			slices.Sort(tagsClone)
			tagsClone = slices.Compact(tagsClone)
			if len(tagsClone) != len(m.Tags) {
				return errors.Errorf("Duplicate tags")
			}
		}

	}

	return nil
}

type CheckUIDArg interface {
	GetUid() string
}

func DoCheckUID(arg string) error {

	if !govalidator.IsUUIDv4(arg) {
		return grpcutils.InvalidArg("Invalid UID")
	}
	return nil
}

func CheckUID(arg CheckUIDArg) error {
	if arg == nil {
		return grpcutils.InvalidArg("Cannot obtain UID")
	}

	if !govalidator.IsUUIDv4(arg.GetUid()) {
		return grpcutils.InvalidArg("Invalid UID")
	}
	return nil
}

type ValidateCommonOpts struct {
	ValidateMetadataOpts
	RequireStatus bool
	RequireData   bool
}

func ValidateCommon(obj umetav1.ResourceObjectI, om *ValidateCommonOpts) error {
	if obj == nil {
		return grpcutils.InvalidArg("Nil Resource")
	}

	if om == nil {
		om = &ValidateCommonOpts{}
	}

	if obj.GetMetadata() == nil {
		return grpcutils.InvalidArg("Resource Metadata must be set")
	}
	if err := ValidateMetadata(obj.GetMetadata(), &om.ValidateMetadataOpts); err != nil {
		return err
	}

	objMap, err := pbutils.ConvertToMap(obj)
	if err != nil {
		return grpcutils.InvalidArg("Invalid Resource unmarshalling")
	}
	specI, ok := objMap["spec"]
	if !ok {
		return grpcutils.InvalidArg("Resource spec must be set")
	}

	_, ok = specI.(map[string]any)
	if !ok {
		return grpcutils.InvalidArg("Invalid Resource spec")
	}

	if om.RequireStatus {
		statusI, ok := objMap["status"]
		if !ok {
			return grpcutils.InvalidArg("Resource status must be set")
		}

		_, ok = statusI.(map[string]any)
		if !ok {
			return grpcutils.InvalidArg("Invalid Resource status")
		}
	}

	if om.RequireData {
		dataI, ok := objMap["data"]
		if !ok {
			return grpcutils.InvalidArg("Resource data must be set")
		}

		_, ok = dataI.(map[string]any)
		if !ok {
			return grpcutils.InvalidArg("Invalid Resource data")
		}
	}

	return nil
}

func GetNameAndParents(arg string) ([]string, error) {
	if err := validateName(arg, 0, 6); err != nil {
		return nil, err
	}

	subNames := strings.Split(arg, ".")
	var ret []string

	for i := 1; i <= len(subNames); i++ {
		args := strings.SplitAfterN(arg, ".", i)
		ret = append(ret, args[i-1])
	}

	return ret, nil
}

func ValidateGenASCII(arg string) error {
	if arg == "" {
		return grpcutils.InvalidArg("Empty value")
	}

	if !govalidator.IsASCII(arg) {
		return grpcutils.InvalidArg("Invalid ASCII: %s", arg)
	}

	if len(arg) > 150 {
		return grpcutils.InvalidArg("Too long: %s", arg)
	}

	return nil
}

type CheckGetOptionsOpts struct {
	HasName     bool
	HasUID      bool
	ParentsMax  uint64
	ParentsMust uint64
}

// var rgxName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

func CheckGetOptions(req *metav1.GetOptions, o *CheckGetOptionsOpts) error {
	if req == nil {
		return grpcutils.InvalidArg("Nil req")
	}

	if req.Name == "" && req.Uid == "" {
		return grpcutils.InvalidArg("Either Name or UID must be set")
	}

	if o == nil {
		o = &CheckGetOptionsOpts{}
	}

	if o.HasName && req.Name == "" {
		return grpcutils.InvalidArg("A name must be set")
	}
	if o.HasUID && req.Uid == "" {
		return grpcutils.InvalidArg("A UID must be set")
	}

	if req.Name != "" {
		if err := validateName(req.Name, o.ParentsMust, o.ParentsMax); err != nil {
			return grpcutils.InvalidArgWithErr(err)
		}
	}

	if req.Uid != "" && !govalidator.IsUUIDv4(req.Uid) {
		return serr.InvalidArg("Invalid UID")
	}

	return nil
}

func CheckDeleteOptions(req *metav1.DeleteOptions, o *CheckGetOptionsOpts) error {
	if req == nil {
		return grpcutils.InvalidArg("Nil req")
	}
	return CheckGetOptions(&metav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	}, o)
}

func CheckObjectRef(req *metav1.ObjectReference, o *CheckGetOptionsOpts) error {
	if req == nil {
		return grpcutils.InvalidArg("Nil req")
	}
	return CheckGetOptions(&metav1.GetOptions{
		Uid:  req.Uid,
		Name: req.Name,
	}, o)
}

func ValidateAttrs(attrs *pbutils.Struct) error {
	if attrs == nil {
		return nil
	}

	if protoBytes, err := pbutils.Marshal(attrs); err != nil {
		return grpcutils.InvalidArg("Could not marshal attrs map")
	} else if len(protoBytes) > 20000 {
		return grpcutils.InvalidArg("Attrs field is too large")
	}

	attrsMap, err := pbutils.ConvertToMap(attrs)
	if err != nil {
		return grpcutils.InvalidArg("Could not convert attrs to map")
	}

	if !isMapCamelCase(attrsMap) {
		return grpcutils.InvalidArg("attrs map keys must be in camelCase")
	}

	return nil
}

func isCamelCase(s string) bool {
	if s == "" {
		return false
	}

	runes := []rune(s)

	if !unicode.IsLower(runes[0]) {
		return false
	}

	for i := 1; i < len(runes); i++ {
		r := runes[i]
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func isMapCamelCase(data map[string]any) bool {
	for key, value := range data {
		if len(key) > 100 {
			return false
		}
		if !isCamelCase(key) {
			return false
		}

		if nestedMap, ok := value.(map[string]any); ok {
			if !isMapCamelCase(nestedMap) {
				return false
			}
		}

	}
	return true
}

func CheckEmailCtx(ctx context.Context, arg string) error {
	if arg == "" {
		return errors.Errorf("Empty email")
	}
	if !govalidator.IsEmail(arg) {
		return errors.Errorf("Invalid email")
	}
	if !govalidator.IsASCII(arg) {
		return errors.Errorf("Invalid email")
	}
	if len(arg) >= 128 {
		return errors.Errorf("Invalid email")
	}

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: time.Second * time.Duration(3),
			}
			return d.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	at := strings.LastIndex(arg, "@")
	if at <= 0 || at > len(arg)-3 {
		return errors.Errorf("Invalid email")
	}
	user := arg[:at]
	host := strings.ToLower(arg[at+1:])
	if len(user) > 64 {
		return errors.Errorf("Invalid email")
	}

	switch host {
	case "localhost", "example.com":
		return errors.Errorf("Invalid email")
	}

	if !govalidator.IsDNSName(host) {
		return errors.Errorf("Invalid email")
	}

	if _, err := r.LookupMX(ctx, host); err != nil {
		return errors.Errorf("Invalid email")
	}

	return nil
}

func CheckEmail(arg string) error {
	return CheckEmailCtx(context.Background(), arg)
}

func CheckIsSystem(arg umetav1.ResourceObjectI) error {
	if arg == nil || arg.GetMetadata() == nil {
		return grpcutils.InvalidArg("Resource has no metadata")
	}

	if arg.GetMetadata().IsSystem {
		return grpcutils.Unauthorized("This is a System Resource")
	}

	return nil
}

func CheckIsSystemHidden(arg umetav1.ResourceObjectI) error {
	if arg == nil || arg.GetMetadata() == nil {
		return grpcutils.InvalidArg("Resource has no metadata")
	}

	if arg.GetMetadata().IsSystemHidden {
		return grpcutils.Unauthorized("This is a hidden System Resource")
	}

	return nil
}

func CheckIsUserHidden(arg umetav1.ResourceObjectI) error {
	if arg == nil || arg.GetMetadata() == nil {
		return grpcutils.InvalidArg("Resource has no metadata")
	}

	if arg.GetMetadata().IsUserHidden || arg.GetMetadata().IsSystemHidden {
		return grpcutils.Unauthorized("This is a hidden System Resource")
	}

	return nil
}

func ObjectReferenceToGetOptions(arg *metav1.ObjectReference) *metav1.GetOptions {
	if arg == nil {
		return &metav1.GetOptions{}
	}
	return &metav1.GetOptions{
		Name: arg.Name,
		Uid:  arg.Uid,
	}
}

func ObjectReferenceToDeleteOptions(arg *metav1.ObjectReference) *metav1.DeleteOptions {
	if arg == nil {
		return &metav1.DeleteOptions{}
	}

	return &metav1.DeleteOptions{
		Name: arg.Name,
		Uid:  arg.Uid,
	}
}

func ValidateHostPort(hostPort string) error {
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return grpcutils.InvalidArg("Invalid host:port %s", hostPort)
	}

	if !govalidator.IsHost(host) {
		return grpcutils.InvalidArg("Invalid host: %s", host)
	}

	if port == "" {
		return grpcutils.InvalidArg("Empty port")
	}

	if !govalidator.IsPort(port) {
		return grpcutils.InvalidArg("Invalid port: %s", port)
	}

	return nil
}

func ValidatePort(d int) error {
	if !govalidator.IsPort(strconv.Itoa(int(d))) {
		return grpcutils.InvalidArg("Invalid port: %d", d)
	}
	return nil
}

func ValidateHTTPStatusCode(arg int64) error {
	if arg < 200 || arg > 599 {
		return grpcutils.InvalidArg("Invalid statusCode: %d", arg)
	}

	return nil
}

func ValidateDuration(d *metav1.Duration) error {
	if d == nil {
		return nil
	}

	seconds := umetav1.ToDuration(d).ToSeconds()

	if seconds < 1 {
		return grpcutils.InvalidArg("duration cannot be shorter than 1 second")
	}
	if seconds > 60*60*24*30*12*100 {
		return grpcutils.InvalidArg("Duration is too big")
	}

	return nil
}

func ValidateEnvVar(key, val string) error {
	if err := ValidateEnvVarKey(key); err != nil {
		return err
	}

	if err := ValidateEnvVarValue(val); err != nil {
		return err
	}

	return nil
}

func ValidateEnvVarValue(val string) error {
	if len(val) > 8129 {
		return grpcutils.InvalidArg("Value is too long: %s", val)
	}

	return nil
}

func ValidateEnvVarKey(key string) error {
	if key == "" {
		return grpcutils.InvalidArg("Key is empty")
	}

	if len(key) > 1024 {
		return grpcutils.InvalidArg("Key is too long: %s", key)
	}

	return nil
}

func ValidateBrowserUserAgent(arg string) error {

	if !govalidator.IsByteLength(arg, 3, 300) {
		return grpcutils.InvalidArg("Invalid user agent length")
	}

	u := ua.Parse(arg)
	if u.Name == "" {
		return grpcutils.InvalidArg("Invalid user agent")
	}

	switch {
	case u.Desktop, u.Mobile:
	case u.IsChrome(), u.IsFirefox(), u.IsSafari(), u.IsEdge(), u.IsOpera(),
		u.IsWindows(), u.IsAndroid(), u.IsChromeOS(), u.IsIOS(), u.IsMacOS():
	default:
		return grpcutils.InvalidArg("Unsupported user agent")
	}

	return nil
}
