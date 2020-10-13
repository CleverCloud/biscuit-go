package biscuit

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/flynn/biscuit-go/datalog"
)

var (
	ErrMissingSymbols = errors.New("biscuit: missing symbols")
)

type Verifier interface {
	AddResource(res string)
	AddOperation(op string)
	SetTime(t time.Time)
	AddFact(fact Fact)
	AddRule(rule Rule)
	AddCaveat(caveat Caveat)
	Verify() error
	Query(rule Rule) (FactSet, error)
	BlockIndexByFactName(name string) (int, error)
	Reset()
	PrintWorld() string
}

type verifier struct {
	biscuit     *Biscuit
	baseWorld   *datalog.World
	baseSymbols *datalog.SymbolTable
	world       *datalog.World
	symbols     *datalog.SymbolTable
	caveats     []Caveat
}

var _ Verifier = (*verifier)(nil)

func NewVerifier(b *Biscuit) (Verifier, error) {
	baseWorld, err := b.generateWorld(b.symbols)
	if err != nil {
		return nil, err
	}

	return &verifier{
		biscuit:     b,
		baseWorld:   baseWorld,
		baseSymbols: b.symbols.Clone(),
		world:       baseWorld.Clone(),
		symbols:     b.symbols.Clone(),
		caveats:     []Caveat{},
	}, nil
}

func (v *verifier) AddResource(res string) {
	fact := Fact{
		Predicate: Predicate{
			Name: "resource",
			IDs: []Atom{
				Symbol("ambient"),
				String(res),
			},
		},
	}
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) AddOperation(op string) {
	fact := Fact{
		Predicate: Predicate{
			Name: "operation",
			IDs: []Atom{
				Symbol("ambient"),
				Symbol(op),
			},
		},
	}
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) SetTime(t time.Time) {
	fact := Fact{
		Predicate: Predicate{
			Name: "time",
			IDs: []Atom{
				Symbol("ambient"),
				Date(t),
			},
		},
	}
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) AddFact(fact Fact) {
	v.world.AddFact(fact.convert(v.symbols))
}

func (v *verifier) AddRule(rule Rule) {
	v.world.AddRule(rule.convert(v.symbols))
}

func (v *verifier) AddCaveat(caveat Caveat) {
	v.caveats = append(v.caveats, caveat)
}

func (v *verifier) Verify() error {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	if v.symbols.Sym("authority") == nil || v.symbols.Sym("ambient") == nil {
		return ErrMissingSymbols
	}

	if err := v.world.Run(); err != nil {
		return err
	}

	var errs []error

	for i, caveat := range v.caveats {
		c := caveat.convert(v.symbols)
		successful := false
		for _, query := range c.Queries {
			res := v.world.QueryRule(query)
			if len(*res) != 0 {
				successful = true
				break
			}
		}
		if !successful {
			errs = append(errs, fmt.Errorf("failed to verify caveat #%d: %s", i, debug.Caveat(c)))
		}
	}

	for bi, blockCaveats := range v.biscuit.Caveats() {
		for ci, caveat := range blockCaveats {
			successful := false
			for _, query := range caveat.Queries {
				res := v.world.QueryRule(query)
				if len(*res) != 0 {
					successful = true
					break
				}
			}
			if !successful {
				errs = append(errs, fmt.Errorf("failed to verify block #%d caveat #%d: %s", bi, ci, debug.Caveat(caveat)))
			}
		}
	}

	if len(errs) > 0 {
		errMsg := make([]string, len(errs))
		for i, e := range errs {
			errMsg[i] = e.Error()
		}
		return fmt.Errorf("biscuit: verification failed: %s", strings.Join(errMsg, ", "))
	}

	return nil
}

func (v *verifier) Query(rule Rule) (FactSet, error) {
	if err := v.world.Run(); err != nil {
		return nil, err
	}

	facts := v.world.QueryRule(rule.convert(v.symbols))

	result := make([]Fact, 0, len(*facts))
	for _, fact := range *facts {
		f, err := fromDatalogFact(v.symbols, fact)
		if err != nil {
			return nil, err
		}

		result = append(result, *f)
	}

	return result, nil
}

// BlockIndexByFactName returns the first block index containing a fact with the given name.
// It starts from the authority block and then move on other blocks in order.
// An error is returned when no fact with the given name can be found.
func (v *verifier) BlockIndexByFactName(name string) (int, error) {
	for _, f := range *v.biscuit.authority.facts {
		if v.symbols.Str(f.Name) == name {
			return 0, nil
		}
	}

	for i, b := range v.biscuit.blocks {
		for _, f := range *b.facts {
			if v.symbols.Str(f.Name) == name {
				return i + 1, nil
			}
		}
	}

	return 0, fmt.Errorf("fact %q not found", name)
}

func (v *verifier) PrintWorld() string {
	debug := datalog.SymbolDebugger{
		SymbolTable: v.symbols,
	}

	return debug.World(v.world)
}

func (v *verifier) Reset() {
	v.caveats = []Caveat{}
	v.world = v.baseWorld.Clone()
	v.symbols = v.baseSymbols.Clone()
}
