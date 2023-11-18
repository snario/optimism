package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/ethereum-optimism/optimism/op-bindings/etherscan"
)

type contractData struct {
	abi          string
	deployedBin  string
	deploymentTx etherscan.TxInfo
}

func (generator *bindGenGeneratorRemote) standardHandler(contractMetadata *remoteContractMetadata) error {
	fetchedData, err := generator.fetchContractData(contractMetadata.Verified, "eth", contractMetadata.Deployments["eth"])
	if err != nil {
		return err
	}

	contractMetadata.DeployedBin = fetchedData.deployedBin

	// If ABI was explicitly provided by config, don't overwrite
	if contractMetadata.Abi == "" {
		contractMetadata.Abi = fetchedData.abi
	} else if fetchedData.abi != "" && contractMetadata.Abi != fetchedData.abi {
		generator.logger.Warn("The given contract ABI differs from what was fetched from Etherscan", "contract", contractMetadata.Name)
		generator.logger.Debug("ABIs", "given", contractMetadata.Abi, "fetched", fetchedData.abi)
	}

	if contractMetadata.InitBin, err = generator.removeDeploymentSalt(fetchedData.deploymentTx.Input, contractMetadata.DeploymentSalt); err != nil {
		return err
	}

	// We're not comparing the bytecode for Create2Deployer with deployment on OP,
	// because we're predeploying a modified version of Create2Deployer that has not yet been
	// deployed to OP.
	// For context: https://github.com/ethereum-optimism/op-geth/pull/126
	if contractMetadata.Name != "Create2Deployer" {
		if err := generator.compareBytecodeWithOp(contractMetadata, true, true); err != nil {
			return fmt.Errorf("error comparing contract bytecode for %s: %w", contractMetadata.Name, err)
		}
	}

	return generator.writeAllOutputs(contractMetadata, remoteContractMetadataTemplate)
}

func (generator *bindGenGeneratorRemote) multiSendHandler(contractMetadata *remoteContractMetadata) error {
	// MultiSend has an immutable that resolves to this(address).
	// Because we're predeploying MultiSend to the same address as on OP,
	// we can use the deployed bytecode directly for the predeploy
	fetchedData, err := generator.fetchContractData(contractMetadata.Verified, "op", contractMetadata.Deployments["op"])
	if err != nil {
		return err
	}

	contractMetadata.Abi = fetchedData.abi
	contractMetadata.DeployedBin = fetchedData.deployedBin
	if contractMetadata.InitBin, err = generator.removeDeploymentSalt(fetchedData.deploymentTx.Input, contractMetadata.DeploymentSalt); err != nil {
		return err
	}

	return generator.writeAllOutputs(contractMetadata, remoteContractMetadataTemplate)
}

func (generator *bindGenGeneratorRemote) senderCreatorHandler(contractMetadata *remoteContractMetadata) error {
	var err error
	contractMetadata.DeployedBin, err = generator.contractDataClients["eth"].FetchDeployedBytecode(contractMetadata.Deployments["eth"])
	if err != nil {
		return fmt.Errorf("error fetching deployed bytecode: %w", err)
	}

	if err := generator.compareBytecodeWithOp(contractMetadata, false, true); err != nil {
		return fmt.Errorf("error comparing contract bytecode for %s: %w", contractMetadata.Name, err)
	}

	return generator.writeAllOutputs(contractMetadata, remoteContractMetadataTemplate)
}

func (generator *bindGenGeneratorRemote) permit2Handler(contractMetadata *remoteContractMetadata) error {
	fetchedData, err := generator.fetchContractData(contractMetadata.Verified, "eth", contractMetadata.Deployments["eth"])
	if err != nil {
		return err
	}

	contractMetadata.Abi = fetchedData.abi
	if contractMetadata.InitBin, err = generator.removeDeploymentSalt(fetchedData.deploymentTx.Input, contractMetadata.DeploymentSalt); err != nil {
		return err
	}

	if !strings.EqualFold(contractMetadata.DeployerAddress, fetchedData.deploymentTx.To) {
		return fmt.Errorf(
			"expected deployer address: %s doesn't match the to address: %s for Permit2's proxy deployment transaction",
			contractMetadata.DeployerAddress,
			fetchedData.deploymentTx.To,
		)
	}

	// We're not comparing deployed bytecode because Permit2 has immutable Solidity variables that
	// are dependent on block.chainid
	if err := generator.compareBytecodeWithOp(contractMetadata, true, false); err != nil {
		return fmt.Errorf("error comparing contract bytecode for %s: %w", contractMetadata.Name, err)
	}

	return generator.writeAllOutputs(contractMetadata, permit2MetadataTemplate)
}

func (generator *bindGenGeneratorRemote) fetchContractData(contractVerified bool, chain, deploymentAddress string) (contractData, error) {
	var data contractData
	var err error

	contractDataClient, ok := generator.contractDataClients[chain]
	if !ok {
		return data, fmt.Errorf("unknown chain, unable to retrieve a contract data client for chain: %s", chain)
	}

	if contractVerified {
		data.abi, err = contractDataClient.FetchAbi(deploymentAddress)
		if err != nil {
			return contractData{}, fmt.Errorf("error fetching ABI: %w", err)
		}
	}

	data.deployedBin, err = contractDataClient.FetchDeployedBytecode(deploymentAddress)
	if err != nil {
		return contractData{}, fmt.Errorf("error fetching deployed bytecode: %w", err)
	}

	deploymentTxHash, err := contractDataClient.FetchDeploymentTxHash(deploymentAddress)
	if err != nil {
		return contractData{}, fmt.Errorf("error fetching deployment transaction hash: %w", err)
	}

	data.deploymentTx, err = contractDataClient.FetchDeploymentTx(deploymentTxHash)
	if err != nil {
		return contractData{}, fmt.Errorf("error fetching deployment transaction data: %w", err)
	}

	return data, nil
}

func (generator *bindGenGeneratorRemote) removeDeploymentSalt(deploymentData, deploymentSalt string) (string, error) {
	if deploymentSalt == "" {
		return deploymentData, nil
	}

	re := regexp.MustCompile(fmt.Sprintf("^0x(%s)", deploymentSalt))
	if !re.MatchString(deploymentData) {
		return "", fmt.Errorf(
			"expected salt: %s to be at the beginning of the contract initialization code: %s, but it wasn't",
			deploymentSalt, deploymentData,
		)
	}
	return re.ReplaceAllString(deploymentData, ""), nil
}

func (generator *bindGenGeneratorRemote) compareBytecodeWithOp(contractMetadataEth *remoteContractMetadata, compareInitialization, compareDeployment bool) error {
	// Passing false here, because true will retrieve contract's ABI, but we don't need it for bytecode comparison
	opContractData, err := generator.fetchContractData(false, "op", contractMetadataEth.Deployments["op"])
	if err != nil {
		return err
	}

	if compareInitialization {
		if opContractData.deploymentTx.Input, err = generator.removeDeploymentSalt(opContractData.deploymentTx.Input, contractMetadataEth.DeploymentSalt); err != nil {
			return err
		}

		if !strings.EqualFold(contractMetadataEth.InitBin, opContractData.deploymentTx.Input) {
			return fmt.Errorf(
				"initialization bytecode on Ethereum doesn't match bytecode on Optimism. contract=%s bytecodeEth=%s bytecodeOp=%s",
				contractMetadataEth.Name,
				contractMetadataEth.InitBin,
				opContractData.deploymentTx.Input,
			)
		}
	}

	if compareDeployment {
		if !strings.EqualFold(contractMetadataEth.DeployedBin, opContractData.deployedBin) {
			return fmt.Errorf(
				"deployed bytecode on Ethereum doesn't match bytecode on Optimism. contract=%s bytecodeEth=%s bytecodeOp=%s",
				contractMetadataEth.Name,
				contractMetadataEth.DeployedBin,
				opContractData.deployedBin,
			)
		}
	}

	return nil
}

func (generator *bindGenGeneratorRemote) writeAllOutputs(contractMetadata *remoteContractMetadata, fileTemplate string) error {
	abiFilePath, bytecodeFilePath, err := writeContractArtifacts(
		generator.logger, generator.tempArtifactsDir, contractMetadata.Name,
		[]byte(contractMetadata.Abi), []byte(contractMetadata.InitBin),
	)
	if err != nil {
		return err
	}

	err = genContractBindings(generator.logger, abiFilePath, bytecodeFilePath, generator.bindingsPackageName, contractMetadata.Name)
	if err != nil {
		return err
	}

	return generator.writeContractMetadata(
		contractMetadata,
		template.Must(template.New("remoteContractMetadata").Parse(fileTemplate)),
	)
}

func (generator *bindGenGeneratorRemote) writeContractMetadata(contractMetadata *remoteContractMetadata, fileTemplate *template.Template) error {
	metadataFilePath := filepath.Join(generator.metadataOut, strings.ToLower(contractMetadata.Name)+"_more.go")
	metadataFile, err := os.OpenFile(
		metadataFilePath,
		os.O_RDWR|os.O_CREATE|os.O_TRUNC,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("error opening %s's metadata file at %s: %w", contractMetadata.Name, metadataFilePath, err)
	}
	defer metadataFile.Close()

	if err := fileTemplate.Execute(metadataFile, contractMetadata); err != nil {
		return fmt.Errorf("error writing %s's contract metadata at %s: %w", contractMetadata.Name, metadataFilePath, err)
	}

	generator.logger.Debug("Successfully wrote contract metadata", "contract", contractMetadata.Name, "path", metadataFilePath)
	return nil
}

// remoteContractMetadataTemplate is a Go text template for generating the metadata
// associated with a remotely sourced contracts.
//
// The template expects the following data to be provided:
// - .Package: the name of the Go package.
// - .Name: the name of the contract.
// - .DeployedBin: the binary (hex-encoded) of the deployed contract.
var remoteContractMetadataTemplate = `// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package {{.Package}}

var {{.Name}}DeployedBin = "{{.DeployedBin}}"
func init() {
	deployedBytecodes["{{.Name}}"] = {{.Name}}DeployedBin
}
`

// permit2MetadataTemplate is a Go text template used to generate metadata
// for remotely sourced Permit2 contract. Because Permit2 has an immutable
// Solidity variables that depends on block.chainid, we can't use the deployed
// bytecode, but instead need to generate it specifically for each chain.
// To help with this, the metadata contains the
//
// The template expects the following data to be provided:
// - .Package: the name of the Go package.
// - .Name: the name of the contract.
// - .InitBin: the binary (hex-encoded) of the contract's initialization code.
// - .DeploymentSalt: the salt used during the contract's deployment.
// - .DeployerAddress: the Ethereum address of the contract's deployer.
var permit2MetadataTemplate = `// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package {{.Package}}

var {{.Name}}InitBin = "{{.InitBin}}"
var {{.Name}}DeploymentSalt = "{{.DeploymentSalt}}"
var {{.Name}}DeployerAddress = "{{.DeployerAddress}}"

func init() {
	initBytecodes["{{.Name}}"] = {{.Name}}InitBin
	deploymentSalts["{{.Name}}"] = {{.Name}}DeploymentSalt
	deployerAddresses["{{.Name}}"] = {{.Name}}DeployerAddress
}
`
