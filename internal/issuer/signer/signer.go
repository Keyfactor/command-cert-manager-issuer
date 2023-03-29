/*
Copyright 2023 Keyfactor.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package signer

import (
	"context"
	commandissuer "github.com/Keyfactor/command-issuer/api/v1alpha1"
	"github.com/Keyfactor/keyfactor-go-client-sdk/api/keyfactor"
)

type commandSigner struct {
	client               *keyfactor.APIClient
	certificateTemplate  string
	certificateAuthority string
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(context.Context, *commandissuer.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(context.Context, []byte) ([]byte, error)
}

type CommandSignerBuilder func(context.Context, *commandissuer.IssuerSpec, map[string][]byte) (Signer, error)

func CommandHealthCheckerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, secretData map[string][]byte) (HealthChecker, error) {
	signer := commandSigner{}

	return &signer, nil
}

func CommandSignerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, secretData map[string][]byte) (Signer, error) {
	signer := commandSigner{}

	return &signer, nil
}

func (s *commandSigner) Check() error {
	return nil
}

func (s *commandSigner) Sign(ctx context.Context, csr []byte) ([]byte, error) {
	return nil, nil
}