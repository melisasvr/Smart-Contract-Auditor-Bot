async function main() {
    const AuditLogger = await ethers.getContractFactory("AuditLogger");
    const auditLogger = await AuditLogger.deploy();
    await auditLogger.deployed();
    console.log("AuditLogger deployed to:", auditLogger.address);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});