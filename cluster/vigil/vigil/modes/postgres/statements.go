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

package postgres

import "github.com/pkg/errors"

const maxStatementNameLen = 63
const maxStatements = 4096
const maxStatementsSize = 128 * 1024 * 1024

type statement struct {
	query       string
	isAmbiguous bool
}

type statementUpdate struct {
	query         string
	hasQuery      bool
	isClosed      bool
	isAmbiguous   bool
	keepsPrevious bool
}

type statements struct {
	committed map[string]statement
	updates   map[string]*statementUpdate
	size      int

	isStarted bool
	isExact   bool
	isClean   bool
}

func newStatements() *statements {
	return &statements{
		committed: make(map[string]statement),
		updates:   make(map[string]*statementUpdate),
	}
}

func getStatementKey(name string) string {
	if len(name) > maxStatementNameLen {
		return name[:maxStatementNameLen]
	}

	return name
}

func (s *statements) start(isIdle, isExact bool) {
	if s.isStarted {
		return
	}

	s.isStarted = true
	s.isClean = isIdle
	s.isExact = isExact
}

func (s *statements) parse(name, query string) error {
	key := getStatementKey(name)
	u := s.getUpdate(key, key == "")

	if u.hasQuery && u.query != query {
		u.isAmbiguous = true
	}

	s.size += len(query) - len(u.query)
	u.query = query
	u.hasQuery = true
	u.isClosed = false
	s.isClean = false

	s.commitIfInexact()

	if len(s.committed)+len(s.updates) > maxStatements || s.size > maxStatementsSize {
		return errors.Errorf("Too many prepared statements")
	}

	return nil
}

func (s *statements) close(name string) {
	s.getUpdate(getStatementKey(name), true).isClosed = true
	s.commitIfInexact()
}

func (s *statements) fail() {
	s.isClean = false
}

func (s *statements) sync() {
	s.commit()
	s.isStarted = false
}

func (s *statements) get(name string) (string, bool) {
	key := getStatementKey(name)

	if u, ok := s.updates[key]; ok {
		return u.query, !u.isClosed
	}

	ret, ok := s.committed[key]
	if !ok || ret.isAmbiguous {
		return "", false
	}

	return ret.query, true
}

func (s *statements) getUpdate(key string, isReplacing bool) *statementUpdate {
	if u, ok := s.updates[key]; ok {
		return u
	}

	ret := &statementUpdate{
		keepsPrevious: !s.isClean || !isReplacing,
	}
	s.updates[key] = ret

	return ret
}

func (s *statements) commitIfInexact() {
	if !s.isExact {
		s.commit()
	}
}

func (s *statements) commit() {
	for key, u := range s.updates {
		prev, hasPrev := s.committed[key]
		hasPrev = hasPrev && u.keepsPrevious

		s.size -= len(u.query) + len(prev.query)
		delete(s.committed, key)

		switch {
		case !u.hasQuery:
			if hasPrev {
				s.setCommitted(key, prev)
			}
		case u.isAmbiguous, hasPrev && (prev.isAmbiguous || prev.query != u.query):
			s.setCommitted(key, statement{isAmbiguous: true})
		default:
			s.setCommitted(key, statement{query: u.query})
		}
	}

	clear(s.updates)
}

func (s *statements) setCommitted(key string, st statement) {
	s.committed[key] = st
	s.size += len(st.query)
}
