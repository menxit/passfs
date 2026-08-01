package passfs

type linkChangeWatcher interface {
	events() <-chan struct{}
	errors() <-chan error
	close() error
}
