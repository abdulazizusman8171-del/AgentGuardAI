const fs = require("fs");
const solc = require("solc");
const ganache = require("ganache");
const { ethers } = require("ethers");

async function main() {
    const sources = {
        "AgentGuardVaultV7.sol": {
            content: fs.readFileSync(
                "../v7/AgentGuardVaultV7.sol", "utf8"
            )
        },
        "V7SecurityFixtures.sol": {
            content: fs.readFileSync(
                "../../tests/blockchain/V7SecurityFixtures.sol", "utf8"
            )
        },
        "AgentGuardFactoryV7.sol": {
            content: fs.readFileSync(
                "../v7/AgentGuardFactoryV7.sol", "utf8"
            )
        }
    };

    const input = {
        language: "Solidity",
        sources,
        settings: {
            optimizer: { enabled: true, runs: 200 },
            outputSelection: {
                "*": {
                    "*": ["abi", "evm.bytecode.object"]
                }
            }
        }
    };

    const output = JSON.parse(solc.compile(JSON.stringify(input)));
    const errors = (output.errors || []).filter(
        e => e.severity === "error"
    );

    if (errors.length) {
        throw new Error(errors.map(e => e.formattedMessage).join("\n"));
    }

    const artifact = (file, name) => output.contracts[file][name];

    const chain = ganache.provider({ logging: { quiet: true } });

    try {
        const provider = new ethers.BrowserProvider(chain);
        const owner = await provider.getSigner(0);
        const recipientA = await provider.getSigner(1);
        const recipientB = await provider.getSigner(2);

        const ownerAddress = await owner.getAddress();
        const addressA = await recipientA.getAddress();
        const addressB = await recipientB.getAddress();

        let passed = 0;

        function check(name, condition) {
            if (!condition) throw new Error("FAILED: " + name);
            passed++;
            console.log("PASS:", name);
        }

        async function expectRevert(name, action, expectedReason) {
            try {
                await action();
            } catch (error) {
                const message = [
                    error.reason,
                    error.shortMessage,
                    error.message
                ].filter(Boolean).join(" ");

                if (!message.includes(expectedReason)) {
                    throw new Error(
                        `${name}: unexpected revert: ${message}`
                    );
                }

                passed++;
                console.log("PASS:", name);
                return;
            }

            throw new Error("FAILED: " + name);
        }


        async function expectUnauthorized(name, action, stateUnchanged) {
            let revertedReceipt = null;

            try {
                const tx = await action({ gasLimit: 500000 });
                await tx.wait();
            } catch (error) {
                revertedReceipt = error.receipt || null;
            }

            if (!revertedReceipt || Number(revertedReceipt.status) !== 0) {
                throw new Error(
                    name + ": expected a mined transaction revert"
                );
            }

            check(name + " reverts", true);
            check(name + " leaves state unchanged", await stateUnchanged());
        }
        const vaultArtifact = artifact(
            "AgentGuardVaultV7.sol", "AgentGuardVaultV7"
        );

        const Vault = new ethers.ContractFactory(
            vaultArtifact.abi,
            vaultArtifact.evm.bytecode.object,
            owner
        );

        const vault = await Vault.deploy(
            ownerAddress,
            ethers.parseEther("1"),
            ethers.parseEther("2")
        );

        await vault.waitForDeployment();

        const vaultAddress = await vault.getAddress();

        await (await owner.sendTransaction({
            to: vaultAddress,
            value: ethers.parseEther("3")
        })).wait();

        // Test 1: Reentrancy protection.
        const reentrantArtifact = artifact(
            "V7SecurityFixtures.sol", "V7ReentrantRecipient"
        );

        const Reentrant = new ethers.ContractFactory(
            reentrantArtifact.abi,
            reentrantArtifact.evm.bytecode.object,
            owner
        );

        const reentrant = await Reentrant.deploy();
        await reentrant.waitForDeployment();

        const reentrantAddress = await reentrant.getAddress();

        await (await reentrant.configure(
            vaultAddress,
            ethers.parseEther("0.1")
        )).wait();

        await (await vault.setRecipientPolicy(
            reentrantAddress,
            true,
            ethers.parseEther("1"),
            ethers.parseEther("1")
        )).wait();

        // Authorization ensures the nested call reaches nonReentrant.
        await (await vault.setExecutor(reentrantAddress, true)).wait();

        const countBefore = await vault.transactionCount();

        await (await vault.execute(
            reentrantAddress,
            ethers.parseEther("0.2")
        )).wait();

        check(
            "Reentrant callback was attempted",
            await reentrant.reentryAttempted()
        );

        check(
            "Reentrant execution was blocked",
            await reentrant.reentryBlocked()
        );

        check(
            "Only the original transfer was recorded",
            (await vault.transactionCount()) === countBefore + 1n
        );

        // Test 2: Rejecting recipient and accounting rollback.
        const rejectingArtifact = artifact(
            "V7SecurityFixtures.sol", "V7RejectingRecipient"
        );

        const Rejecting = new ethers.ContractFactory(
            rejectingArtifact.abi,
            rejectingArtifact.evm.bytecode.object,
            owner
        );

        const rejecting = await Rejecting.deploy();
        await rejecting.waitForDeployment();

        const rejectingAddress = await rejecting.getAddress();

        await (await vault.setRecipientPolicy(
            rejectingAddress,
            true,
            ethers.parseEther("1"),
            ethers.parseEther("1")
        )).wait();

        const globalBefore = await vault.getCurrentDaySpending();
        const countBeforeReject = await vault.transactionCount();

        await expectRevert(
            "Rejecting recipient causes transfer failure",
            () => vault.execute.staticCall(
                rejectingAddress,
                ethers.parseEther("0.3")
            ),
            "Transfer failed"
        );

        let rejectedTransactionFailed = false;

        try {
            const tx = await vault.execute(
                rejectingAddress,
                ethers.parseEther("0.3"),
                { gasLimit: 500000 }
            );
            await tx.wait();
        } catch (error) {
            rejectedTransactionFailed = true;
        }

        check(
            "Rejecting recipient transaction reverts",
            rejectedTransactionFailed
        );

        check(
            "Failed transfer does not increase global spending",
            (await vault.getCurrentDaySpending()) === globalBefore
        );

        check(
            "Failed transfer does not increase transaction count",
            (await vault.transactionCount()) === countBeforeReject
        );

        const rejectingPolicy = await vault.recipientPolicies(
            rejectingAddress
        );

        check(
            "Failed transfer does not increase recipient spending",
            rejectingPolicy.dailySpent === 0n
        );

        // Test 3: Global daily spending across different recipients.
        await (await vault.setRecipientPolicy(
            addressA, true,
            ethers.parseEther("1"),
            ethers.parseEther("1")
        )).wait();

        await (await vault.setRecipientPolicy(
            addressB, true,
            ethers.parseEther("1"),
            ethers.parseEther("1")
        )).wait();

        await (await vault.execute(
            addressA, ethers.parseEther("0.9")
        )).wait();

        await (await vault.execute(
            addressB, ethers.parseEther("0.9")
        )).wait();

        check(
            "Global daily spending includes multiple recipients",
            (await vault.getCurrentDaySpending()) ===
                ethers.parseEther("2")
        );

        await expectRevert(
            "Global daily limit blocks spending across recipients",
            () => vault.execute.staticCall(
                addressA,
                ethers.parseEther("0.01")
            ),
            "Global daily limit"
        );

        // Test 4: Recovery authorization and failed-recipient protection.
        const recoveryVault = await Vault.deploy(
            ownerAddress,
            ethers.parseEther("1"),
            ethers.parseEther("2")
        );

        await recoveryVault.waitForDeployment();

        const recoveryVaultAddress = await recoveryVault.getAddress();

        await (await owner.sendTransaction({
            to: recoveryVaultAddress,
            value: ethers.parseEther("1.5")
        })).wait();

        await expectUnauthorized(
            "Unauthorized wallet cannot initiate recovery",
            overrides => recoveryVault.connect(recipientA).initiateRecovery(addressB, overrides),
            async () =>
                (await recoveryVault.recoveryReadyAt()) === 0n &&
                (await recoveryVault.pendingRecoveryRecipient()) === ethers.ZeroAddress
        );

        await (await recoveryVault.initiateRecovery(
            rejectingAddress
        )).wait();

        const authorizedRecoveryTime = await recoveryVault.recoveryReadyAt();

        await expectUnauthorized(
            "Unauthorized wallet cannot cancel recovery",
            overrides => recoveryVault.connect(recipientA).cancelRecovery(overrides),
            async () =>
                (await recoveryVault.recoveryReadyAt()) === authorizedRecoveryTime &&
                (await recoveryVault.pendingRecoveryRecipient()) === rejectingAddress
        );

        await expectUnauthorized(
            "Unauthorized wallet cannot execute recovery",
            overrides => recoveryVault.connect(recipientA).executeRecovery(overrides),
            async () =>
                (await recoveryVault.recoveryReadyAt()) === authorizedRecoveryTime &&
                (await recoveryVault.pendingRecoveryRecipient()) === rejectingAddress
        );

        const recoveryReadyBefore = await recoveryVault.recoveryReadyAt();
        const recoveryBalanceBefore = await recoveryVault.getBalance();

        // Advance the local test blockchain beyond the recovery delay.
        await chain.request({
            method: "evm_increaseTime",
            params: [24 * 60 * 60 + 1]
        });

        await chain.request({
            method: "evm_mine",
            params: []
        });

        await expectRevert(
            "Rejecting recipient blocks emergency recovery",
            () => recoveryVault.executeRecovery.staticCall(),
            "Recovery transfer failed"
        );

        let recoveryTransactionFailed = false;

        try {
            const tx = await recoveryVault.executeRecovery({
                gasLimit: 500000
            });
            await tx.wait();
        } catch (error) {
            recoveryTransactionFailed = true;
        }

        check(
            "Failed recovery transaction reverts",
            recoveryTransactionFailed
        );

        check(
            "Failed recovery preserves vault balance",
            (await recoveryVault.getBalance()) === recoveryBalanceBefore
        );

        check(
            "Failed recovery preserves recovery timer",
            (await recoveryVault.recoveryReadyAt()) === recoveryReadyBefore
        );

        check(
            "Failed recovery preserves pending recipient",
            (await recoveryVault.pendingRecoveryRecipient()) ===
                rejectingAddress
        );

        // Owner can cancel and initiate recovery to another recipient.
        await (await recoveryVault.cancelRecovery()).wait();

        check(
            "Owner can cancel failed recovery",
            (await recoveryVault.recoveryReadyAt()) === 0n
        );

        await (await recoveryVault.initiateRecovery(addressA)).wait();

        check(
            "Owner can initiate recovery with a replacement recipient",
            (await recoveryVault.pendingRecoveryRecipient()) === addressA
        );
        console.log("\nV7 ADVERSARIAL SECURITY RESULTS");
        console.log("Passed:", passed);
        console.log("Failed: 0");
        console.log("ADVERSARIAL SUITE: PASSED");

    } finally {
        await chain.disconnect();
    }
}

main().catch(error => {
    console.error("\nADVERSARIAL TEST FAILURE:", error);
    process.exitCode = 1;
});





