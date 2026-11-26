const fs = require("fs");
const path = require("path");
const solc = require("solc");
const ganache = require("ganache");
const { ethers } = require("ethers");

async function main() {
    const input = {
        language: "Solidity",
        sources: {
            "AgentGuardVaultV7.sol": {
                content: fs.readFileSync("../v7/AgentGuardVaultV7.sol", "utf8")
            },
            "AgentGuardFactoryV7.sol": {
                content: fs.readFileSync("../v7/AgentGuardFactoryV7.sol", "utf8")
            }
        },
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

    if (output.errors?.some(e => e.severity === "error")) {
        throw new Error(output.errors.map(e => e.formattedMessage).join("\n"));
    }

    const factoryArtifact =
        output.contracts["AgentGuardFactoryV7.sol"].AgentGuardFactoryV7;

    const vaultArtifact =
        output.contracts["AgentGuardVaultV7.sol"].AgentGuardVaultV7;

    const chain = ganache.provider({ logging: { quiet: true } });
    let passed = 0;

    function check(name, condition) {
        if (!condition) throw new Error("FAILED: " + name);
        passed++;
        console.log("PASS:", name);
    }

    async function expectRevert(name, action) {
        try {
            await action();
        } catch {
            passed++;
            console.log("PASS:", name);
            return;
        }
        throw new Error("FAILED: " + name);
    }

    try {
        const provider = new ethers.BrowserProvider(chain);
        const owner = await provider.getSigner(0);
        const attacker = await provider.getSigner(1);
        const recipient = await provider.getSigner(2);
        const executor = await provider.getSigner(3);

        const ownerAddress = await owner.getAddress();
        const attackerAddress = await attacker.getAddress();
        const recipientAddress = await recipient.getAddress();
        const executorAddress = await executor.getAddress();

        const Factory = new ethers.ContractFactory(
            factoryArtifact.abi,
            factoryArtifact.evm.bytecode.object,
            owner
        );

        const factory = await Factory.deploy();
        await factory.waitForDeployment();

        const tx = await factory.createVault(
            ethers.parseEther("1"),
            ethers.parseEther("3")
        );
        await tx.wait();

        const vaultAddress = await factory.vaultOf(ownerAddress);

        const vault = new ethers.Contract(
            vaultAddress,
            vaultArtifact.abi,
            owner
        );

        check(
            "Factory creates an independently owned vault",
            (await vault.owner()).toLowerCase() === ownerAddress.toLowerCase()
        );

        await expectRevert(
            "Unauthorized wallet cannot change vault limits",
            () => vault.connect(attacker).setLimits(
                ethers.parseEther("1"),
                ethers.parseEther("3")
            )
        );

        await expectRevert(
            "Duplicate vault creation is rejected",
            async () => {
                const duplicate = await factory.createVault(
                    ethers.parseEther("1"),
                    ethers.parseEther("3")
                );
                await duplicate.wait();
            }
        );

        await (await vault.setRecipientPolicy(
            recipientAddress,
            true,
            ethers.parseEther("1"),
            ethers.parseEther("1.5")
        )).wait();

        await (await owner.sendTransaction({
            to: vaultAddress,
            value: ethers.parseEther("3")
        })).wait();

        await expectRevert(
            "Unauthorized wallet cannot execute a transfer",
            () => vault.connect(attacker).execute(
                recipientAddress,
                ethers.parseEther("0.1")
            )
        );

        await expectRevert(
            "Transaction limit is enforced",
            () => vault.execute(
                recipientAddress,
                ethers.parseEther("1.1")
            )
        );

        await (await vault.execute(
            recipientAddress,
            ethers.parseEther("1")
        )).wait();

        console.log("DEBUG recipient spending:",
            ethers.formatEther(await vault.getRecipientDailySpending(recipientAddress))
        );
        console.log("DEBUG global spending:",
            ethers.formatEther(await vault.getCurrentDaySpending())
        );
        console.log("DEBUG recipient policy:",
            await vault.recipientPolicies(recipientAddress)
        );

        await expectRevert(
            "Recipient daily spending limit is enforced",
            () => vault.execute(
                recipientAddress,
                ethers.parseEther("1")
            )
        );

        await (await vault.setRecipientPolicy(
            recipientAddress,
            true,
            ethers.parseEther("1"),
            ethers.parseEther("3")
        )).wait();

        await (await vault.setExecutor(executorAddress, true)).wait();

        check(
            "Executor authorization is enabled",
            await vault.authorizedExecutors(executorAddress)
        );

        await (await vault.setExecutor(executorAddress, false)).wait();

        check(
            "Executor revocation takes effect immediately",
            !(await vault.authorizedExecutors(executorAddress))
        );

        await expectRevert(
            "Revoked executor cannot execute transfers",
            () => vault.connect(executor).execute(
                recipientAddress,
                ethers.parseEther("0.1")
            )
        );

        const recoveryRecipient = attackerAddress;

        await (await vault.initiateRecovery(recoveryRecipient)).wait();

        check(
            "Recovery immediately pauses normal execution",
            await vault.paused()
        );

        await expectRevert(
            "Recovery cannot execute before 24 hours",
            () => vault.executeRecovery()
        );

        await chain.request({
            method: "evm_increaseTime",
            params: [24 * 60 * 60 + 60]
        });

        await chain.request({
            method: "evm_mine",
            params: []
        });

        const readyAt = await vault.recoveryReadyAt();
        const latestBlock = await chain.request({
            method: "eth_getBlockByNumber",
            params: ["latest", false]
        });

        const latestTimestamp = parseInt(latestBlock.timestamp, 16);

        console.log("\nRECOVERY TIMER DIAGNOSTICS");
        console.log("Recovery ready timestamp:", readyAt.toString());
        console.log("Latest block timestamp:", latestTimestamp);
        console.log("Seconds remaining:", Number(readyAt) - latestTimestamp);

        await (await vault.executeRecovery({ gasLimit: 500000 })).wait();

        check(
            "Owner can recover funds after 24 hours",
            (await provider.getBalance(vaultAddress)) === 0n
        );

        const secondOwner = await provider.getSigner(4);
        const secondAddress = await secondOwner.getAddress();

        await (await factory.connect(secondOwner).createVault(
            ethers.parseEther("1"),
            ethers.parseEther("3")
        )).wait();

        const secondVaultAddress = await factory.vaultOf(secondAddress);

        const secondVault = new ethers.Contract(
            secondVaultAddress,
            vaultArtifact.abi,
            secondOwner
        );

        await expectRevert(
            "First user cannot pause another user's vault",
            () => secondVault.connect(owner).setPaused(true)
        );

        await expectRevert(
            "First user cannot initiate another user's recovery",
            () => secondVault.connect(owner).initiateRecovery(recipientAddress)
        );

        await (await secondVault.initiateRecovery(recipientAddress)).wait();
        await (await secondVault.cancelRecovery()).wait();

        check(
            "Owner can cancel pending recovery",
            (await secondVault.recoveryReadyAt()) === 0n
        );

        check(
            "Vault remains paused after recovery cancellation",
            await secondVault.paused()
        );

        await (await secondVault.setPaused(false)).wait();

        check(
            "Owner can unpause after cancelling recovery",
            !(await secondVault.paused())
        );

        console.log("\nV7 SECURITY TEST RESULTS");
        console.log("Passed:", passed);
        console.log("Failed: 0");
        console.log("LOCAL TEST SUITE: PASSED");

    } finally {
        await chain.disconnect();
    }
}

main().catch(error => {
    console.error("\nSECURITY TEST FAILURE:", error);
    process.exitCode = 1;
});





