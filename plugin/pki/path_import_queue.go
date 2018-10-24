package pki

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
)

// This returns the list of queued for import to TPP certificates
func pathImportQueue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathUpdateImportQueue,
		},

		HelpSynopsis:    pathFetchHelpSyn,
		HelpDescription: pathFetchHelpDesc,
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func pathImportQueueList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue-list/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			//TODO: don't know why but ListOperation returning  "No value found at venafi-pki-import/import-queue-list/import/" error
			logical.ReadOperation: b.pathFetchImportQueueList,
		},

		HelpSynopsis:    pathFetchHelpSyn,
		HelpDescription: pathFetchHelpDesc,
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func (b *backend) pathFetchImportQueueList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roleName := data.Get("role").(string)
	log.Printf("Using role: %s", roleName)
	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathUpdateImportQueue(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roleName := data.Get("role").(string)
	log.Printf("Using role: %s", roleName)
	b.importToTPP(data, ctx, req)
	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}
