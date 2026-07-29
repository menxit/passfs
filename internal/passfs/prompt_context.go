package passfs

import (
	"context"

	"filippo.io/age"
)

type cancellationPrompter struct {
	prompter Prompter
	shutdown context.Context
}

type cancellationIdentityPrompter struct {
	cancellationPrompter
	identityPrompter IdentityPrompter
}

// WithCancellation makes every prompt stop when shutdown is cancelled. Service
// shutdown must not wait for an interactive authorization that is holding a
// FUSE request open.
func WithCancellation(prompter Prompter, shutdown context.Context) Prompter {
	base := cancellationPrompter{
		prompter: prompter,
		shutdown: shutdown,
	}
	if identityPrompter, ok := prompter.(IdentityPrompter); ok {
		return &cancellationIdentityPrompter{
			cancellationPrompter: base,
			identityPrompter:     identityPrompter,
		}
	}
	return &base
}

func (p *cancellationPrompter) Prompt(
	ctx context.Context,
	request PromptRequest,
) (string, error) {
	promptContext, cancel := combinePromptContexts(ctx, p.shutdown)
	defer cancel()
	return p.prompter.Prompt(promptContext, request)
}

func (p *cancellationIdentityPrompter) PromptIdentity(
	ctx context.Context,
	request PromptRequest,
) (*age.X25519Identity, error) {
	promptContext, cancel := combinePromptContexts(ctx, p.shutdown)
	defer cancel()
	return p.identityPrompter.PromptIdentity(promptContext, request)
}

func combinePromptContexts(
	request context.Context,
	shutdown context.Context,
) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(request)
	stopShutdown := context.AfterFunc(shutdown, cancel)
	return ctx, func() {
		stopShutdown()
		cancel()
	}
}
