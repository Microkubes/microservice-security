package db

import (
	"sync"
	"testing"

	"golang.org/x/net/context"

	"github.com/JormungandrK/backends"
	"github.com/Microkubes/microservice-tools/config"
)

func TestExtendBackend(t *testing.T) {
	backend := &backends.RepositoriesBackend{}

	repoExtender := func(repo backends.Repository) backends.Repository {
		return repo
	}

	extended := extendBackend(backend, repoExtender)
	if extended == nil {
		t.Fatal("Extended backend must nut be nil.")
	}

	if _, ok := extended.(*ExtendedBackend); !ok {
		t.Fatal("Expected the backend to be of type *ExtendedBackend.")
	}
}

type defaultRepo struct {
	backends.Repository
}

type extendedRepo struct {
	backends.Repository
}

func TestDefineRepository(t *testing.T) {
	repoBuilder := func(def backends.RepositoryDefinition, backend backends.Backend) (backends.Repository, error) {
		return &defaultRepo{}, nil
	}
	backend := backends.NewRepositoriesBackend(context.Background(), &config.DBInfo{}, repoBuilder, func() {})

	extended := &ExtendedBackend{
		Backend:  backend,
		extended: map[string]backends.Repository{},
		extendRepo: func(repo backends.Repository) backends.Repository {
			return &extendedRepo{}
		},
	}

	repo, err := extended.DefineRepository("test_collection", backends.RepositoryDefinitionMap{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.(*extendedRepo); !ok {
		t.Fatal("Expected to get an extended repo instead of the default repo type.")
	}
}

func TestGetRepository(t *testing.T) {
	repoBuilder := func(def backends.RepositoryDefinition, backend backends.Backend) (backends.Repository, error) {
		return &defaultRepo{}, nil
	}
	backend := backends.NewRepositoriesBackend(context.Background(), &config.DBInfo{}, repoBuilder, func() {})

	extended := &ExtendedBackend{
		Backend: backend,
		extended: map[string]backends.Repository{
			"test_collection": &extendedRepo{},
		},
		extendRepo: func(repo backends.Repository) backends.Repository {
			return &extendedRepo{}
		},
	}

	repo, err := extended.GetRepository("test_collection")
	if err != nil {
		t.Fatal(err)
	}
	if repo == nil {
		t.Fatal("Expected to get the Repository instead of nil.")
	}
	if _, ok := repo.(*extendedRepo); !ok {
		t.Fatal("Expected to get an extended repo instead of the default repo type.")
	}
}

type defaultBackendManager struct {
	backends.BackendManager
}

type defaultBackend struct {
	backends.Backend
}

func (d *defaultBackendManager) GetBackend(name string) (backends.Backend, error) {
	return &defaultBackend{}, nil
}

func TestWrapBackendManager(t *testing.T) {

	extendedManager := WrapBackendManager(&defaultBackendManager{}, map[string]RepoExtender{})

	if extendedManager == nil {
		t.Fatal("Expected to get the extended backend manager instead of nil.")
	}

}

func TestGetBackend(t *testing.T) {
	repoExtender := func(repo backends.Repository) backends.Repository {
		return &extendedRepo{
			Repository: repo,
		}
	}
	extendedManager := &ExtendedBackendManager{
		BackendManager: &defaultBackendManager{},
		extended:       map[string]backends.Backend{},
		lock:           sync.Mutex{},
		repoExtenders: map[string]RepoExtender{
			"test_db_type": repoExtender,
		},
	}

	backend, err := extendedManager.GetBackend("test_db_type")
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := backend.(*ExtendedBackend); !ok {
		t.Fatal("Expected the created backend to be of type *ExtendedBackend.")
	}
}
