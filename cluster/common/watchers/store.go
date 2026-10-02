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

package watchers

import (
	"bytes"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/octelium/octelium/apis/main/metav1"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	tombstoneTTL           = 10 * time.Minute
	tombstonePruneInterval = 1 * time.Minute
)

type storeItem struct {
	resourceVersion string
	item            *anypb.Any
}

type itemStore struct {
	mu sync.Mutex

	items      map[string]*storeItem
	tombstones map[string]time.Time

	lastPrunedAt time.Time
}

func (s *itemStore) init() {
	if s.items == nil {
		s.items = make(map[string]*storeItem)
	}

	if s.tombstones == nil {
		s.tombstones = make(map[string]time.Time)
	}
}

func (s *itemStore) set(md *metav1.Metadata, item *anypb.Any) (*storeItem, bool) {
	uid := md.GetUid()
	if uid == "" {
		return nil, true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.init()

	if _, ok := s.tombstones[uid]; ok {
		return nil, false
	}

	prev, ok := s.items[uid]
	if ok && !isNewerResourceVersion(md, prev.resourceVersion) {
		return nil, false
	}

	s.items[uid] = &storeItem{
		resourceVersion: md.GetResourceVersion(),
		item:            item,
	}

	return prev, true
}

func (s *itemStore) delete(md *metav1.Metadata) bool {
	uid := md.GetUid()
	if uid == "" {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.init()

	if _, ok := s.tombstones[uid]; ok {
		return false
	}

	delete(s.items, uid)

	now := time.Now()
	s.tombstones[uid] = now
	s.pruneTombstones(now)

	return true
}

func (s *itemStore) forget(uid, resourceVersion string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if itm, ok := s.items[uid]; ok && itm.resourceVersion == resourceVersion {
		delete(s.items, uid)
	}
}

func (s *itemStore) pruneTombstones(now time.Time) {
	if now.Sub(s.lastPrunedAt) < tombstonePruneInterval {
		return
	}

	s.lastPrunedAt = now

	for uid, deletedAt := range s.tombstones {
		if now.Sub(deletedAt) > tombstoneTTL {
			delete(s.tombstones, uid)
		}
	}
}

func isNewerResourceVersion(md *metav1.Metadata, curResourceVersion string) bool {
	resourceVersion := md.GetResourceVersion()

	switch {
	case resourceVersion == "" || curResourceVersion == "":
		return true
	case resourceVersion == curResourceVersion:
		return false
	case md.GetLastResourceVersion() == curResourceVersion:
		return true
	}

	newUUID, err := uuid.Parse(resourceVersion)
	if err != nil || newUUID.Version() != 7 {
		return true
	}

	curUUID, err := uuid.Parse(curResourceVersion)
	if err != nil || curUUID.Version() != 7 {
		return true
	}

	return bytes.Compare(newUUID[:], curUUID[:]) > 0
}
