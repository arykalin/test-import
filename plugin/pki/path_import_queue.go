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
		//Pattern: `import-queue/(?P<queueRole>[0-9A-Fa-f]+)`,
		//Fields: map[string]*framework.FieldSchema{
		//	"queueRole": &framework.FieldSchema{
		//		Type: framework.TypeString,
		//		Description: `Queue role name`,
		//	},
		//},

		Pattern: "import-queue/import/",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathFetchImportQueueList,
		},

		HelpSynopsis:    pathFetchHelpSyn,
		HelpDescription: pathFetchHelpDesc,
	}
	//var fields map[string]*framework.FieldSchema
	//fields["role"] = &framework.FieldSchema{
	//	Type: framework.TypeString,
	//	Description: `The desired role with configuration for this
	//request`,
	//	}
	//ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func (b *backend) pathFetchImportQueueList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	//roleName := data.Get("role").(string)
	//log.Printf("Using role: %s", roleName)
	//entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("queueRole").(string)+"/")
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
