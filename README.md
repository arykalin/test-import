# Vault PKI backend plugin with import to Venafi Platform

## Requirements for Venafi Platform policy

   1. Policy should have default template configured

   2. Currently vcert (which is used in Venafi issuers) supports only user provided CSR. So it is must be set in the policy.

   3. MSCA configuration should have http URI set before the ldap URI in X509 extensions, otherwise NGINX ingress controller couldn't get certificate chain from URL and OSCP will not work. Example:

   ```
   X509v3 extensions:
       X509v3 Subject Alternative Name:
       DNS:test-cert-manager1.venqa.venafi.com}}
       X509v3 Subject Key Identifier: }}
       61:5B:4D:40:F2:CF:87:D5:75:5E:58:55:EF:E8:9E:02:9D:E1:81:8E}}
       X509v3 Authority Key Identifier: }}
       keyid:3C:AC:9C:A6:0D:A1:30:D4:56:A7:3D:78:BC:23:1B:EC:B4:7B:4D:75}}X509v3 CRL Distribution Points:Full Name:
       URI:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl}}
       URI:ldap:///CN=QA%20Venafi%20CA,CN=qavenafica,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint}}{{Authority Information Access: }}
       CA Issuers - URI:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt}}
       CA Issuers - URI:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority}}
   ```

   4. Option in Venafi Platform CA configuration template "Automatically include CN as DNS SAN" should be set to true.


## Quickstart

1. Read about Vault plugin system https://www.vaultproject.io/docs/internals/plugins.html

1. Download the plugin binary from releases page

1. Configure your Vault to use plugin_directory where you download the plugin. Use vault-config.hcl from this repo as example.

1. Start your Vault.

1. Get sha256 checksum of plugin binary:
`
shasum -a 256 download_plugin_path/venafi-pki-import
`

1. Add plugin to the vault system catalog:
`
vault write sys/plugins/catalog/venafi-pki-import sha_256="SHA256 CHECKSUM" command="venafi-pki-import"
`

1. Enable plugin secret backend:
`
vault secrets enable -path=pki-import -plugin-name=venafi-pki-import plugin
`

1. Create PKI role (https://www.vaultproject.io/docs/secrets/pki/index.html). You will need to add following Venafi Platform options:


		tpp_import="true"
		tpp_url=<URL of Venafi Platform Example: https://venafi.example.com/vedsdk>
		tpp_user=<web API user for Venafi Platfrom Example: admin>
		tpp_password=<Password for web API user Example: password>
		zone=<Prepared Platform policy>

    Example:
    ```
    vault write venafi-pki-import/roles/import \
    	tpp_import="true"  \
    	tpp_url=https://venafi.example.com/vedsdk \
    	tpp_user=admin \
    	tpp_password=password \
    	zone="vault\\prepared-policy" \
    	generate_lease=true store_by_cn="true" store_pkey="true" store_by_serial="true" ttl=1h max_ttl=1h \
    	allowed_domains=import.example.com \
    	allow_subdomains=true
    ```

1. Sign certificate and import it using standart PKI command. Example:

    ```
    vault write venafi-pki-import/issue/import \
        common_name="import1.import.example.com" \
        alt_names="alt1.import.example.com,alt2-hbpxs.import.example.com"
    ```



## Quickstart for developers

1. Export your Venafi Platform configuration variables

    ```
    export TPPUSER=<web API user for Venafi Platfrom Example: admin>
    export TPPPASSWORD=<Password for web API user Example: password>
    export TPPURL=<URL of Venafi Platform Example: https://venafi.example.com/vedsdk>
    export TPPZONE=<Prepared Platform policy>
    ```

    Platform policy name could be tricky. If you have spaces enter policy in double quotes:
    ```
    export TPPZONE="My Policy"
    ```

    And if you have backslash (nested policy) you should enter four backslashes:
    ```
    export TPPZONE="first\\\\second"
    ```

2. Run `make dev_server` to start Vault server

3. Run `make dev` to sign random certificate and import it to the Platform.