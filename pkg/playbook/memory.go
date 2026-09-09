package playbook

import (
	"context"
	"sort"
	"strconv"
	"sync"
)

// MemoryCatalog implements the same transaction and immutability contract as PostgreSQL.
// It is intended for tests and explicitly ephemeral operation.
type MemoryCatalog struct{ *catalog }

func NewMemoryCatalog(options ...CatalogOption) *MemoryCatalog {
	return &MemoryCatalog{newCatalog(&memoryBackend{tables: make(map[string]map[string]catalogRow)}, options)}
}

type memoryBackend struct {
	mu     sync.Mutex
	tables map[string]map[string]catalogRow
}
type memoryTx struct {
	tables map[string]map[string]catalogRow
}

func memoryKey(id string, version int) string { return id + "\x00" + strconv.Itoa(version) }
func (b *memoryBackend) read(ctx context.Context, fn func(catalogTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return fn(&memoryTx{b.tables})
}
func (b *memoryBackend) write(ctx context.Context, fn func(catalogTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	tables := make(map[string]map[string]catalogRow, len(b.tables))
	for table, rows := range b.tables {
		copyRows := make(map[string]catalogRow, len(rows))
		for k, v := range rows {
			copyRows[k] = v
		}
		tables[table] = copyRows
	}
	if err := fn(&memoryTx{tables}); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b.tables = tables
	return nil
}
func (tx *memoryTx) get(ctx context.Context, table, id string, version int) (catalogRow, error) {
	if err := ctx.Err(); err != nil {
		return catalogRow{}, err
	}
	row, ok := tx.tables[table][memoryKey(id, version)]
	if !ok {
		return catalogRow{}, ErrCatalogNotFound
	}
	return row, nil
}
func (tx *memoryTx) lookup(ctx context.Context, table, key string) (catalogRow, error) {
	if err := ctx.Err(); err != nil {
		return catalogRow{}, err
	}
	for _, row := range tx.tables[table] {
		if row.Lookup == key {
			return row, nil
		}
	}
	return catalogRow{}, ErrCatalogNotFound
}
func (tx *memoryTx) each(ctx context.Context, table string, state LifecycleState, fn func(catalogRow) (bool, error)) error {
	rows := make([]catalogRow, 0, len(tx.tables[table]))
	for _, row := range tx.tables[table] {
		if state == "" || row.State == state {
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].ID != rows[j].ID {
			return rows[i].ID < rows[j].ID
		}
		return rows[i].Version < rows[j].Version
	})
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		more, err := fn(row)
		if err != nil {
			return err
		}
		if !more {
			break
		}
	}
	return nil
}
func (tx *memoryTx) insert(ctx context.Context, table string, row catalogRow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx.tables[table] == nil {
		tx.tables[table] = make(map[string]catalogRow)
	}
	key := memoryKey(row.ID, row.Version)
	if _, ok := tx.tables[table][key]; ok {
		return ErrCatalogConflict
	}
	if table == "sources" || table == "learning_candidates" || table == "playbooks" {
		for _, old := range tx.tables[table] {
			if old.Lookup == row.Lookup {
				return ErrCatalogConflict
			}
		}
	}
	tx.tables[table][key] = row
	return nil
}
func (tx *memoryTx) state(ctx context.Context, id string, version int, state LifecycleState) error {
	row, err := tx.get(ctx, "playbooks", id, version)
	if err != nil {
		return err
	}
	row.State = state
	tx.tables["playbooks"][memoryKey(id, version)] = row
	return nil
}
func (tx *memoryTx) count(ctx context.Context, table string, state LifecycleState) (int, error) {
	n := 0
	err := tx.each(ctx, table, state, func(catalogRow) (bool, error) { n++; return true, nil })
	return n, err
}

var _ Catalog = (*MemoryCatalog)(nil)

func (tx *memoryTx) replaceFinding(ctx context.Context, row catalogRow) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx.tables["findings"] == nil {
		tx.tables["findings"] = make(map[string]catalogRow)
	}
	tx.tables["findings"][memoryKey(row.ID, 0)] = row
	return nil
}
