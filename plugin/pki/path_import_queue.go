package pki

import (
	"context"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
	"time"
)

// This returns the list of queued for import to TPP certificates
func pathImportQueue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathUpdateImportQueue,
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
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

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
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
	//Running import queue in background
	ctx = context.Background()
	go func() {
		for {
			go b.importToTPP(data, ctx, req)
			time.Sleep(30 * time.Second)
		}
	}()

	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) importToTPP(data *framework.FieldData, ctx context.Context, req *logical.Request) {
	log.Println("!!!!Checking import lock!!!!")
	b.importQueue.Lock()
	defer b.importQueue.Unlock()
	log.Println("!!!!Starting new import routine!!!!")
	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		log.Printf("Could not get queue list: %s", err)
	}
	log.Printf("Queue list is:\n %s", entries)
	for {
		/*TODO: it will be good to import every new entry in new vcert client. For it you will need to create new client object here
		and start it in go routine
		*/
		for i, sn := range entries {

			log.Printf("Trying to import certificate with SN %s at pos %d", sn, i)
			cl, err := b.ClientVenafi(ctx, req.Storage, data, req, data.Get("role").(string))
			log.Println(cl)
			if err != nil {
				log.Printf("Could not create venafi client: %s", err)
			} else {
				certEntry, err := req.Storage.Get(ctx, "import-queue/"+data.Get("role").(string)+"/"+sn)
				if err != nil {
					log.Printf("Could not get certificate from import-queue/%s: %s", sn, err)
				}
				block := pem.Block{
					Type:  "CERTIFICATE",
					Bytes: certEntry.Value,
				}
				certString := string(pem.EncodeToMemory(&block))
				log.Printf("Importing cert: %s", certString)
				importReq := &certificate.ImportRequest{
					// if PolicyDN is empty, it is taken from cfg.Zone
					ObjectName:      sn,
					CertificateData: certString,
					PrivateKeyData:  "",
					Password:        "",
					Reconcile:       false,
				}
				importResp, err := cl.ImportCertificate(importReq)
				if err != nil {
					log.Printf("could not import certificate: %s", err)
					return
				}
				log.Printf("Certificate imported:\n %s", pp(importResp))
				log.Printf("Removing certificate from import queue")
				err = req.Storage.Delete(ctx, "import-queue/"+data.Get("role").(string)+"/"+sn)
				if err != nil {
					log.Printf("Could not delete sn from queue: %s", err)
				} else {
					log.Printf("Cedrtificate with SN %s removed from queue", sn)
					entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
					if err != nil {
						log.Printf("Could not get queue list: %s", err)
					} else {
						log.Printf("Queue is:\n %s", entries)
					}
				}
			}

			//There will be no new entries, need to find a way to refresh them. Try recursion here
		}
		log.Println("Waiting for new entries")
		time.Sleep(15 * time.Second)
	}
}

const pathImportQueueSyn = `
Fetch a CA, CRL, CA Chain, or non-revoked certificate.
`

const pathImportQueueDesc = `
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.

Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.

Using "ca_chain" as the value fetches the certificate authority trust chain in PEM encoding.
`
