package pki

import (
	"context"
	"fmt"
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
		Pattern: "import-queue/",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathFetchImportQueueList,
		},

		HelpSynopsis:    pathFetchHelpSyn,
		HelpDescription: pathFetchHelpDesc,
	}
	return ret
}

func (b *backend) pathFetchImportQueueList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roles, err := req.Storage.List(ctx, "import-queue/")
	var entries []string
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		log.Printf("Getting entry %s", role)
		rawEntry, err := req.Storage.List(ctx, "import-queue/"+role)
		if err != nil {
			return nil, err
		}
		var entry []string
		for _, e := range rawEntry {
			entry = append(entry, fmt.Sprintf("%s: %s", role, e))
		}
		entries = append(entries, entry...)
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
