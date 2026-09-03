package whalewall

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mitchellh/copystructure"
	"go.uber.org/zap"
)

const anonSetName = "__set%d"

type firewallClient interface {
	AddTable(t *nftables.Table) *nftables.Table

	AddChain(c *nftables.Chain) *nftables.Chain
	DelChain(c *nftables.Chain)
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)

	AddSet(s *nftables.Set, vals []nftables.SetElement) error
	DelSet(s *nftables.Set)
	GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
	GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error

	AddRule(r *nftables.Rule) *nftables.Rule
	DelRule(r *nftables.Rule) error
	InsertRule(r *nftables.Rule) *nftables.Rule
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)

	Flush() error
}

type mockFirewall struct {
	logger *zap.SugaredLogger

	changed bool

	tables map[string]*table
	chains map[string]chain

	unsetLookupExprs []*expr.Lookup

	flushErr error

	bf baseFirewallReaderWriter
}

type table struct {
	Sets       setMap
	SetSchemas map[string]*nftables.Set

	newAnonSets map[string]bool
}

type setMap map[string][]nftables.SetElement

type chain struct {
	Chain *nftables.Chain
	Rules []*nftables.Rule
}

type baseFirewallReaderWriter interface {
	readBaseFirewall(f func(base *mockFirewall))
	writeBaseFirewall(f func(base *mockFirewall))
	allocateAnonSetID() uint32
	allocateRuleHandle() uint64
}

type mockFirewallCreatorI interface {
	newMockFirewall() *mockFirewall
	baseFirewallReaderWriter
}

func newMockFirewallCreator(logger *zap.Logger) mockFirewallCreatorI {
	m := &mockFirewallCreator{
		baseFirewall: &mockFirewall{
			tables: make(map[string]*table),
			chains: make(map[string]chain),
		},
		logger: logger,
	}

	return m
}

type mockFirewallCreator struct {
	baseFirewall *mockFirewall
	mtx          sync.RWMutex
	logger       *zap.Logger
	nextSetID    atomic.Uint32
	nextRuleID   atomic.Uint64
}

func (m *mockFirewallCreator) newMockFirewall() *mockFirewall {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	newFirewall := &mockFirewall{
		logger: m.logger.Sugar(),
		tables: clone(m.baseFirewall.tables),
		chains: clone(m.baseFirewall.chains),
		bf:     m,
	}
	initTables(newFirewall)

	return newFirewall
}

func initTables(m *mockFirewall) {
	for _, t := range m.tables {
		t.newAnonSets = make(map[string]bool)
		if t.SetSchemas == nil {
			t.SetSchemas = make(map[string]*nftables.Set)
		}
	}
}

func (m *mockFirewallCreator) allocateAnonSetID() uint32 {
	return m.nextSetID.Add(1)
}

func (m *mockFirewallCreator) allocateRuleHandle() uint64 {
	return m.nextRuleID.Add(1)
}

func (m *mockFirewallCreator) readBaseFirewall(f func(base *mockFirewall)) {
	m.mtx.RLock()
	f(m.baseFirewall)
	m.mtx.RUnlock()
}

func (m *mockFirewallCreator) writeBaseFirewall(f func(base *mockFirewall)) {
	m.mtx.Lock()
	f(m.baseFirewall)
	m.mtx.Unlock()
}

func (m *mockFirewall) AddTable(t *nftables.Table) *nftables.Table {
	m.changed = true

	if _, ok := m.tables[t.Name]; !ok {
		m.tables[t.Name] = &table{
			Sets:        make(setMap),
			SetSchemas:  make(map[string]*nftables.Set),
			newAnonSets: make(map[string]bool),
		}
	}

	return t
}

func (m *mockFirewall) AddChain(c *nftables.Chain) *nftables.Chain {
	m.changed = true

	if existing, ok := m.chains[c.Name]; !ok {
		m.chains[c.Name] = chain{
			Chain: c,
		}
	} else if !chainSchemasEqual(existing.Chain, c) {
		m.logger.Errorf("chain %q has incompatible schema", c.Name)
		m.flushErr = syscall.EEXIST
	}

	return c
}

func (m *mockFirewall) DelChain(c *nftables.Chain) {
	m.changed = true

	chain, ok := m.chains[c.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", c.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	if len(chain.Rules) != 0 {
		m.logger.Errorf("chain %q is not empty", c.Name)
		m.flushErr = syscall.EBUSY
		return
	}
	for _, other := range m.chains {
		for _, rule := range other.Rules {
			for _, expression := range rule.Exprs {
				if verdict, ok := expression.(*expr.Verdict); ok && verdict.Chain == c.Name {
					m.logger.Errorf("chain %q is still referenced by rule", c.Name)
					m.flushErr = syscall.EBUSY
					return
				}
			}
		}
	}
	for _, table := range m.tables {
		for _, elements := range table.Sets {
			for _, element := range elements {
				if element.VerdictData != nil && element.VerdictData.Chain == c.Name {
					m.logger.Errorf("chain %q is still referenced by verdict map", c.Name)
					m.flushErr = syscall.EBUSY
					return
				}
			}
		}
	}
	delete(m.chains, c.Name)
}

func (m *mockFirewall) ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error) {
	var chains []*nftables.Chain
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		for _, c := range base.chains {
			if c.Chain.Table.Family == family {
				chains = append(chains, c.Chain)
			}
		}
	})

	return chains, nil
}

func (m *mockFirewall) AddSet(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	setName := s.Name
	if s.Anonymous {
		setID := m.bf.allocateAnonSetID()
		setName = fmt.Sprintf(anonSetName, setID)
		s.ID = setID
		s.Name = anonSetName
		t.newAnonSets[setName] = false
	}

	if existing, ok := t.SetSchemas[setName]; ok {
		if !setSchemasEqual(existing, s) {
			m.logger.Errorf("set %q has incompatible schema", setName)
			m.flushErr = syscall.EEXIST
		}
		return nil
	}
	t.Sets[setName] = vals
	schema := clone(s)
	schema.Name = setName
	t.SetSchemas[setName] = schema
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) DelSet(s *nftables.Set) {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	delete(t.Sets, s.Name)
	delete(t.SetSchemas, s.Name)
	m.tables[s.Table.Name] = t
}

func (m *mockFirewall) GetSetByName(table *nftables.Table, name string) (*nftables.Set, error) {
	var (
		set *nftables.Set
		err error
	)
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		t, ok := base.tables[table.Name]
		if !ok {
			err = syscall.ENOENT
			return
		}
		schema, ok := t.SetSchemas[name]
		if !ok {
			err = syscall.ENOENT
			return
		}
		set = clone(schema)
	})
	return set, err
}

func (m *mockFirewall) GetSetElements(s *nftables.Set) ([]nftables.SetElement, error) {
	var (
		elements []nftables.SetElement
		retErr   error
	)
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		table, ok := base.tables[s.Table.Name]
		if !ok {
			retErr = syscall.ENOENT
			return
		}
		setElements, ok := table.Sets[s.Name]
		if !ok {
			retErr = syscall.ENOENT
			return
		}
		if !setSchemasEqual(table.SetSchemas[s.Name], s) {
			retErr = syscall.EINVAL
			return
		}
		elements = clone(setElements)
	})
	return elements, retErr
}

func (m *mockFirewall) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.Sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}
	if !setSchemasEqual(t.SetSchemas[s.Name], s) {
		m.logger.Errorf("set %q has incompatible schema", s.Name)
		m.flushErr = syscall.EINVAL
		return nil
	}

	// don't add elements already present in set
	for _, val := range vals {
		if !slices.ContainsFunc(elements, func(e nftables.SetElement) bool {
			if !bytes.Equal(e.Key, val.Key) {
				return false
			}
			if !bytes.Equal(e.Val, val.Val) {
				return false
			}
			if !bytes.Equal(e.KeyEnd, val.KeyEnd) {
				return false
			}
			if e.IntervalEnd != val.IntervalEnd {
				return false
			}
			if (e.VerdictData != nil) != (val.VerdictData != nil) {
				return false
			}
			if e.VerdictData != nil {
				if e.VerdictData.Kind != val.VerdictData.Kind {
					return false
				}
				if e.VerdictData.Chain != val.VerdictData.Chain {
					return false
				}
			}
			if e.Timeout != val.Timeout {
				return false
			}
			return true
		}) {
			elements = append(elements, val)
		}
	}

	t.Sets[s.Name] = elements
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	m.changed = true

	t, ok := m.tables[s.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", s.Table.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}

	elements, ok := t.Sets[s.Name]
	if !ok {
		m.logger.Errorf("set %q not found", s.Name)
		m.flushErr = syscall.ENOENT
		return nil
	}
	if !setSchemasEqual(t.SetSchemas[s.Name], s) {
		m.logger.Errorf("set %q has incompatible schema", s.Name)
		m.flushErr = syscall.EINVAL
		return nil
	}

	for _, v := range vals {
		i := slices.IndexFunc(elements, func(e nftables.SetElement) bool {
			if !bytes.Equal(e.Key, v.Key) {
				return false
			}
			if !bytes.Equal(e.KeyEnd, v.KeyEnd) {
				return false
			}
			if !bytes.Equal(e.Val, v.Val) {
				return false
			}
			return e.IntervalEnd == v.IntervalEnd
		})
		if i == -1 {
			m.logger.Errorf("set element with key %v not found", v.Key)
			m.flushErr = syscall.ENOENT
			continue
		}
		elements = slices.Delete(elements, i, i+1)
	}
	t.Sets[s.Name] = elements
	m.tables[s.Table.Name] = t

	return nil
}

func (m *mockFirewall) AddRule(r *nftables.Rule) *nftables.Rule {
	m.changed = true
	if r.Handle != 0 {
		m.logger.Errorf("new rule unexpectedly carries stale handle %d", r.Handle)
		m.flushErr = syscall.EINVAL
		return r
	}

	t, ok := m.tables[r.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return r
	}
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	// copy this rule so if we update it after flush the caller's rule
	// won't be updated
	rCopy := clone(r)
	if rCopy.Handle == 0 {
		rCopy.Handle = m.bf.allocateRuleHandle()
	}
	m.checkRule(rCopy, t)

	c.Rules = append(c.Rules, rCopy)
	m.chains[r.Chain.Name] = c

	return r
}

func (m *mockFirewall) DelRule(r *nftables.Rule) error {
	m.changed = true
	if r.Handle == 0 {
		m.flushErr = syscall.EINVAL
		return errors.New("rule deletion requires an actual nonzero handle")
	}

	m.delRule(r, false)

	return nil
}

func (m *mockFirewall) delRule(r *nftables.Rule, softDel bool) {
	if _, ok := m.tables[r.Table.Name]; !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return
	}
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return
	}

	i := slices.IndexFunc(c.Rules, func(r2 *nftables.Rule) bool { return r.Handle == r2.Handle })
	if i == -1 {
		m.logger.Error("rule not found")
		m.flushErr = syscall.ENOENT
		return
	}

	// delete any anonymous sets associated with this rule
	for _, ruleExpr := range c.Rules[i].Exprs {
		lookupExpr, ok := ruleExpr.(*expr.Lookup)
		if !ok || !strings.HasPrefix(lookupExpr.SetName, "__set") {
			continue
		}

		m.DelSet(&nftables.Set{
			Table: c.Rules[i].Table,
			Name:  lookupExpr.SetName,
		})
	}

	if !softDel {
		c.Rules = slices.Delete(c.Rules, i, i+1)
		m.chains[r.Chain.Name] = c
	}
}

func (m *mockFirewall) InsertRule(r *nftables.Rule) *nftables.Rule {
	m.changed = true
	if r.Handle != 0 {
		m.logger.Errorf("new rule unexpectedly carries stale handle %d", r.Handle)
		m.flushErr = syscall.EINVAL
		return r
	}

	t, ok := m.tables[r.Table.Name]
	if !ok {
		m.logger.Errorf("table %q not found", r.Table.Name)
		m.flushErr = syscall.ENOENT
		return r
	}
	c, ok := m.chains[r.Chain.Name]
	if !ok {
		m.logger.Errorf("chain %q not found", r.Chain.Name)
		m.flushErr = syscall.ENOENT
		return r
	}

	// copy this rule so if we update it after flush the caller's rule
	// won't be updated
	rCopy := clone(r)
	if rCopy.Handle == 0 {
		rCopy.Handle = m.bf.allocateRuleHandle()
	}
	m.checkRule(rCopy, t)

	c.Rules = slices.Insert(c.Rules, 0, rCopy)
	m.chains[r.Chain.Name] = c

	return r
}

func (m *mockFirewall) checkRule(r *nftables.Rule, t *table) {
	for _, ruleExpr := range r.Exprs {
		switch e := ruleExpr.(type) {
		case *expr.Lookup:
			lookup := e
			if lookup.SetName != anonSetName {
				if _, ok := t.Sets[lookup.SetName]; !ok {
					m.logger.Errorf("lookup set %q not found", lookup.SetName)
					m.flushErr = syscall.ENOENT
				}
				continue
			}
			if lookup.SetID == 0 {
				m.flushErr = syscall.EINVAL
				continue
			}
			// mark this expression to be updated after flush
			m.unsetLookupExprs = append(m.unsetLookupExprs, lookup)

			setName := fmt.Sprintf(anonSetName, lookup.SetID)
			if _, ok := t.newAnonSets[setName]; ok {
				// mark this anonymous set as valid now that a rule has
				// been added that uses it
				t.newAnonSets[setName] = true
			} else {
				m.logger.Errorf("anonymous lookup set %q not found", setName)
				m.flushErr = syscall.ENOENT
			}
		case *expr.Verdict:
			if (e.Kind == expr.VerdictJump || e.Kind == expr.VerdictGoto) && e.Chain != "" {
				if _, ok := m.chains[e.Chain]; !ok {
					m.logger.Errorf("verdict chain %q not found", e.Chain)
					m.flushErr = syscall.ENOENT
				}
			}
		}
	}
}

func (m *mockFirewall) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	var rules []*nftables.Rule
	var err error
	m.bf.readBaseFirewall(func(base *mockFirewall) {
		ch, ok := base.chains[c.Name]
		if !ok {
			err = syscall.ENOENT
			return
		}
		rules = clone(ch.Rules)
	})

	return rules, err
}

func (m *mockFirewall) Flush() error {
	defer func() {
		m.changed = false
		m.bf.readBaseFirewall(func(base *mockFirewall) {
			m.tables = clone(base.tables)
			initTables(m)
			m.chains = clone(base.chains)
		})
		m.flushErr = nil
	}()

	if m.flushErr != nil {
		return m.flushErr
	}

	// update lookup expressions
	for _, lookupExpr := range m.unsetLookupExprs {
		lookupExpr.SetName = fmt.Sprintf(lookupExpr.SetName, lookupExpr.SetID)
		lookupExpr.SetID = 0
	}
	m.unsetLookupExprs = nil

	// delete unused anonymous sets
	for _, t := range m.tables {
		for newAnonSet, used := range t.newAnonSets {
			if !used {
				delete(t.Sets, newAnonSet)
			}
		}
	}

	// only propagate changes if there were changes made
	if m.changed {
		m.bf.writeBaseFirewall(func(base *mockFirewall) {
			base.tables = m.tables
			base.chains = m.chains
		})
	}

	return nil
}

func setSchemasEqual(a, b *nftables.Set) bool {
	if a == nil || b == nil || a.Table == nil || b.Table == nil {
		return false
	}
	return a.Table.Name == b.Table.Name &&
		a.Table.Family == b.Table.Family &&
		a.Anonymous == b.Anonymous &&
		a.Constant == b.Constant &&
		a.Interval == b.Interval &&
		a.AutoMerge == b.AutoMerge &&
		a.IsMap == b.IsMap &&
		a.HasTimeout == b.HasTimeout &&
		a.Counter == b.Counter &&
		a.Dynamic == b.Dynamic &&
		a.Concatenation == b.Concatenation &&
		a.Timeout == b.Timeout &&
		a.KeyType == b.KeyType &&
		a.DataType == b.DataType &&
		a.Size == b.Size
}

func chainSchemasEqual(a, b *nftables.Chain) bool {
	if a == nil || b == nil || a.Table == nil || b.Table == nil {
		return false
	}
	return a.Name == b.Name &&
		a.Table.Name == b.Table.Name &&
		a.Table.Family == b.Table.Family &&
		pointersEqual(a.Hooknum, b.Hooknum) &&
		pointersEqual(a.Priority, b.Priority) &&
		pointersEqual(a.Policy, b.Policy) &&
		a.Type == b.Type && a.Device == b.Device
}

func pointersEqual[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func clone[T any](t T) T {
	//nolint: forcetypeassert
	return copystructure.Must(copystructure.Copy(t)).(T)
}
