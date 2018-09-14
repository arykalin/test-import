package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
)

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, data *framework.FieldData, req *logical.Request, roleName string) (
	endpoint.Connector, error) {
	log.Printf("Using role: %s", roleName)
	if roleName == "" {
		return nil, fmt.Errorf("Missing role name")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("Unknown role %v", role)
	}

	var cfg *vcert.Config
	log.Printf("Using Venafi Platform with url %s\n", role.TPPURL)
	cfg = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       role.TPPURL,
		Credentials: &endpoint.Authentication{
			User:     role.TPPUser,
			Password: role.TPPPassword,
		},
		Zone:       role.Zone,
		LogVerbose: true,
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}

	log.Printf("Venafi vcert client. type = %T, p = %p, v = %v\n", client, &client, client)
	return client, nil

}

func pp(a interface{}) string {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return fmt.Sprintf(string(b))
}
