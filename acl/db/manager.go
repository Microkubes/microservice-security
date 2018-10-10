package db

import (
	"fmt"
	"sync"

	"github.com/JormungandrK/backends"
)

type ExtendedBackend struct {
	backends.Backend
	extendRepo func(repo backends.Repository) backends.Repository
}

type RepoExtender func(backends.Repository) backends.Repository

func (eb *ExtendedBackend) DefineRepository(name string, def backends.RepositoryDefinition) (backends.Repository, error) {
	repo, err := eb.Backend.DefineRepository(name, def)
	if err != nil {
		return nil, err
	}
	return eb.extendRepo(repo), nil
}

func extendBackend(backend backends.Backend, extendRepo RepoExtender) backends.Backend {
	return &ExtendedBackend{
		Backend:    backend,
		extendRepo: extendRepo,
	}
}

type ExtendedBackendManager struct {
	backends.BackendManager
	extended      map[string]backends.Backend
	repoExtenders map[string]RepoExtender
	lock          sync.Mutex
}

func (em *ExtendedBackendManager) GetBackend(backendType string) (backends.Backend, error) {
	backend, err := em.BackendManager.GetBackend(backendType)
	if err != nil {
		return nil, err
	}
	em.lock.Lock()
	if _, ok := em.extended[backendType]; ok {
		em.lock.Unlock()
		return backend, nil
	}
	repoExtender, ok := em.repoExtenders[backendType]
	if !ok {
		return nil, fmt.Errorf("cannot extend backed of type %s", backendType)
	}
	backend = extendBackend(backend, repoExtender)
	em.extended[backendType] = backend
	em.lock.Unlock()
	return backend, nil
}

func WrapBackendManager(manager backends.BackendManager, supportedBackends map[string]RepoExtender) *ExtendedBackendManager {
	if supportedBackends == nil {
		supportedBackends = map[string]RepoExtender{}
	}
	return &ExtendedBackendManager{
		BackendManager: manager,
		extended:       map[string]backends.Backend{},
		repoExtenders:  supportedBackends,
		lock:           sync.Mutex{},
	}
}
