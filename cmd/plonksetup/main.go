package main

import (
	"fmt"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/test/unsafekzg"
)

const (
	circuitFile = "artifacts/membership_depth6.ccs"
	pkFile      = "artifacts/membership_depth6.pk"
	vkFile      = "artifacts/membership_depth6.vk"

	expectedConstraints = 23957357
)

func main() {

	fmt.Println("============================================================")
	fmt.Println("PLONK SETUP -- UNIVERSAL DEPTH-6 MEMBERSHIP CIRCUIT")
	fmt.Println("============================================================")

	// ============================================================
	// 1. REFUSE TO OVERWRITE AN EXISTING SETUP
	// ============================================================

	if _, err := os.Stat(pkFile); err == nil {
		panic(
			fmt.Errorf(
				"proving key already exists at %s; refusing to regenerate setup",
				pkFile,
			),
		)
	}

	if _, err := os.Stat(vkFile); err == nil {
		panic(
			fmt.Errorf(
				"verifying key already exists at %s; refusing to regenerate setup",
				vkFile,
			),
		)
	}

	// ============================================================
	// 2. LOAD SAVED CCS
	//
	// NO frontend.Compile() ANYWHERE IN THIS PROGRAM.
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("LOADING SAVED CIRCUIT")
	fmt.Println("============================================================")

	circuitHandle, err :=
		os.Open(circuitFile)

	if err != nil {
		panic(
			fmt.Errorf(
				"open circuit: %w",
				err,
			),
		)
	}

	ccs :=
		plonk.NewCS(
			ecc.BN254,
		)

	bytesRead, err :=
		ccs.ReadFrom(
			circuitHandle,
		)

	if err != nil {
		_ = circuitHandle.Close()

		panic(
			fmt.Errorf(
				"read circuit: %w",
				err,
			),
		)
	}

	if err :=
		circuitHandle.Close(); err != nil {

		panic(err)
	}

	fmt.Printf(
		"Circuit bytes       = %d\n",
		bytesRead,
	)

	fmt.Printf(
		"Constraints         = %d\n",
		ccs.GetNbConstraints(),
	)

	fmt.Printf(
		"Secret variables    = %d\n",
		ccs.GetNbSecretVariables(),
	)

	fmt.Printf(
		"Public variables    = %d\n",
		ccs.GetNbPublicVariables(),
	)

	if ccs.GetNbConstraints() !=
		expectedConstraints {

		panic(
			fmt.Errorf(
				"unexpected constraint count: got %d expected %d",
				ccs.GetNbConstraints(),
				expectedConstraints,
			),
		)
	}

	// ============================================================
	// 3. SHOW REQUIRED PLONK SRS SIZE
	// ============================================================

	sizeCanonical, sizeLagrange :=
		plonk.SRSSize(
			ccs,
		)

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("PLONK SRS REQUIREMENTS")
	fmt.Println("============================================================")

	fmt.Printf(
		"Canonical SRS size = %d\n",
		sizeCanonical,
	)

	fmt.Printf(
		"Lagrange SRS size  = %d\n",
		sizeLagrange,
	)

	// ============================================================
	// 4. CREATE SRS CACHE DIRECTORY
	// ============================================================

	cacheDir :=
		"artifacts/kzg-cache"

	if err :=
		os.MkdirAll(
			cacheDir,
			0755,
		); err != nil {

		panic(err)
	}

	// ============================================================
	// 5. GENERATE PLONK SRS
	// ============================================================
	//
	// This is UNSAFE test/benchmark SRS generation.
	//
	// Fine for our experiment.
	// Do not treat this as a production trusted setup.
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("GENERATING PLONK SRS")
	fmt.Println("============================================================")

	srsStart :=
		time.Now()

	srsCanonical,
		srsLagrange,
		err :=
		unsafekzg.NewSRS(
			ccs,
			unsafekzg.WithCacheDir(
				cacheDir,
			),
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"SRS generation failed: %w",
				err,
			),
		)
	}

	srsDuration :=
		time.Since(
			srsStart,
		)

	fmt.Printf(
		"SRS generation time = %v\n",
		srsDuration,
	)

	// ============================================================
	// 6. PLONK SETUP
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("RUNNING PLONK SETUP")
	fmt.Println("============================================================")

	setupStart :=
		time.Now()

	pk,
		vk,
		err :=
		plonk.Setup(
			ccs,
			srsCanonical,
			srsLagrange,
		)

	if err != nil {
		panic(
			fmt.Errorf(
				"PLONK setup failed: %w",
				err,
			),
		)
	}

	setupDuration :=
		time.Since(
			setupStart,
		)

	fmt.Printf(
		"PLONK setup time = %v\n",
		setupDuration,
	)

	// ============================================================
	// 7. SAVE PROVING KEY
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("SAVING PROVING KEY")
	fmt.Println("============================================================")

	pkHandle, err :=
		os.Create(
			pkFile,
		)

	if err != nil {
		panic(err)
	}

	pkBytes, err :=
		pk.WriteTo(
			pkHandle,
		)

	if err != nil {
		_ = pkHandle.Close()
		panic(err)
	}

	if err :=
		pkHandle.Close(); err != nil {

		panic(err)
	}

	fmt.Printf(
		"PK file  = %s\n",
		pkFile,
	)

	fmt.Printf(
		"PK bytes = %d\n",
		pkBytes,
	)

	// ============================================================
	// 8. SAVE VERIFYING KEY
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("SAVING VERIFYING KEY")
	fmt.Println("============================================================")

	vkHandle, err :=
		os.Create(
			vkFile,
		)

	if err != nil {
		panic(err)
	}

	vkBytes, err :=
		vk.WriteTo(
			vkHandle,
		)

	if err != nil {
		_ = vkHandle.Close()
		panic(err)
	}

	if err :=
		vkHandle.Close(); err != nil {

		panic(err)
	}

	fmt.Printf(
		"VK file  = %s\n",
		vkFile,
	)

	fmt.Printf(
		"VK bytes = %d\n",
		vkBytes,
	)

	// ============================================================
	// 9. RELOAD PK
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("RELOADING SAVED PROVING KEY")
	fmt.Println("============================================================")

	pkInput, err :=
		os.Open(
			pkFile,
		)

	if err != nil {
		panic(err)
	}

	loadedPK :=
		plonk.NewProvingKey(
			ecc.BN254,
		)

	pkRead, err :=
		loadedPK.ReadFrom(
			pkInput,
		)

	if err != nil {
		_ = pkInput.Close()
		panic(err)
	}

	if err :=
		pkInput.Close(); err != nil {

		panic(err)
	}

	fmt.Printf(
		"Reloaded PK bytes = %d\n",
		pkRead,
	)

	// ============================================================
	// 10. RELOAD VK
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("RELOADING SAVED VERIFYING KEY")
	fmt.Println("============================================================")

	vkInput, err :=
		os.Open(
			vkFile,
		)

	if err != nil {
		panic(err)
	}

	loadedVK :=
		plonk.NewVerifyingKey(
			ecc.BN254,
		)

	vkRead, err :=
		loadedVK.ReadFrom(
			vkInput,
		)

	if err != nil {
		_ = vkInput.Close()
		panic(err)
	}

	if err :=
		vkInput.Close(); err != nil {

		panic(err)
	}

	fmt.Printf(
		"Reloaded VK bytes = %d\n",
		vkRead,
	)

	// Keep references alive through the reload test.
	_ = loadedPK
	_ = loadedVK

	// ============================================================
	// SUCCESS
	// ============================================================

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("UNIVERSAL PLONK SETUP SAVED SUCCESSFULLY")
	fmt.Println("============================================================")

	fmt.Printf(
		"Circuit      = %s\n",
		circuitFile,
	)

	fmt.Printf(
		"Constraints  = %d\n",
		ccs.GetNbConstraints(),
	)

	fmt.Printf(
		"PK           = %s\n",
		pkFile,
	)

	fmt.Printf(
		"VK           = %s\n",
		vkFile,
	)

	fmt.Printf(
		"SRS time     = %v\n",
		srsDuration,
	)

	fmt.Printf(
		"Setup time   = %v\n",
		setupDuration,
	)

	fmt.Println()
	fmt.Println(
		"frontend.Compile() calls in this program = 0",
	)

	fmt.Println(
		"Next: load this same CCS + PK to prove different keys.",
	)
}
