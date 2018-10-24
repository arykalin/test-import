package pki

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// This returns the list of queued for import to TPP certificates
func pathImportQueue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "import-queue/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation:   b.pathFetchImportQueueList,
			logical.UpdateOperation: b.pathUpdateImportQueue,
		},

		HelpSynopsis:    pathFetchHelpSyn,
		HelpDescription: pathFetchHelpDesc,
	}
}

func (b *backend) pathFetchImportQueueList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	entries, err := req.Storage.List(ctx, "import-queue/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathUpdateImportQueue(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	b.importToTPP(data, ctx, req)
	entries, err := req.Storage.List(ctx, "import-queue/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
