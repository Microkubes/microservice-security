package db

import (
	"fmt"
	"sync"

	"github.com/JormungandrK/backends"
)

// ExtendedBackend wraps a backends.Backend and adds capabilities for creating repositories
// with extended functionalities.
type ExtendedBackend struct {
	backends.Backend
	extendRepo RepoExtender
	extended   map[string]backends.Repository
}

// RepoExtender extends (decorates) exiting backends.Repository with additional capabilities.
// This is a decorator function type. The return value must also be backends.Repository.
type RepoExtender func(backends.Repository) backends.Repository

// DefineRepository defines a repository and extends it with a registered RepoExtender, if available.
func (eb *ExtendedBackend) DefineRepository(name string, def backends.RepositoryDefinition) (backends.Repository, error) {
	repo, err := eb.Backend.DefineRepository(name, def)
	if err != nil {
		return nil, err
	}

	extended := eb.extendRepo(repo)
	eb.extended[name] = extended

	return extended, nil
}

// GetRepository returns a defined extended repository .
func (eb *ExtendedBackend) GetRepository(name string) (backends.Repository, error) {
	if repo, ok := eb.extended[name]; ok {
		return repo, nil
	}
	return nil, backends.ErrBackendError("repository not defined")
}

func extendBackend(backend backends.Backend, extendRepo RepoExtender) backends.Backend {
	return &ExtendedBackend{
		Backend:    backend,
		extendRepo: extendRepo,
		extended:   map[string]backends.Repository{},
	}
}

// ExtendedBackendManager wraps backends.BackendManager that manages extended Backends.
type ExtendedBackendManager struct {
	backends.BackendManager
	extended      map[string]backends.Backend
	repoExtenders map[string]RepoExtender
	lock          sync.Mutex
}

// GetBackend returns extended backends.Backend.
func (em *ExtendedBackendManager) GetBackend(backendType string) (backends.Backend, error) {
	backend, err := em.BackendManager.GetBackend(backendType)
	if err != nil {
		return nil, err
	}
	em.lock.Lock()
	if extendBackend, ok := em.extended[backendType]; ok {
		em.lock.Unlock()
		return extendBackend, nil
	}
	repoExtender, ok := em.repoExtenders[backendType]
	if !ok {
		em.lock.Unlock()
		return nil, fmt.Errorf("cannot extend backed of type %s", backendType)
	}
	extendedBackend := extendBackend(backend, repoExtender)
	em.extended[backendType] = extendedBackend
	em.lock.Unlock()
	return extendedBackend, nil
}

// WrapBackendManager wraps an existing backends.BackendManager into an ExtendedBackendManager.
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
