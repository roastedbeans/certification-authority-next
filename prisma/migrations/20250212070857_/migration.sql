-- CreateTable
CREATE TABLE "Organization" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "opType" TEXT NOT NULL,
    "orgCode" TEXT NOT NULL,
    "orgType" TEXT NOT NULL,
    "authType" TEXT NOT NULL,
    "industry" TEXT NOT NULL,
    "serialNum" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Organization_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "orgCode" TEXT NOT NULL,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Certificate" (
    "id" TEXT NOT NULL,
    "serialNumber" TEXT NOT NULL,
    "certTxId" TEXT NOT NULL,
    "signTxId" TEXT NOT NULL,
    "phoneNumber" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "userCI" TEXT NOT NULL,
    "requestTitle" TEXT NOT NULL,
    "consentType" TEXT NOT NULL,
    "deviceCode" TEXT NOT NULL,
    "deviceBrowser" TEXT NOT NULL,
    "issuedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "revoked" BOOLEAN NOT NULL DEFAULT false,
    "revokedAt" TIMESTAMP(3),
    "revocationReason" TEXT,
    "certificateAuthorityId" TEXT NOT NULL,

    CONSTRAINT "Certificate_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Consent" (
    "id" TEXT NOT NULL,
    "txId" TEXT NOT NULL,
    "consentTitle" TEXT NOT NULL,
    "consent" TEXT NOT NULL,
    "consentLen" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "userId" TEXT,
    "certificateId" TEXT,

    CONSTRAINT "Consent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SignedConsent" (
    "id" TEXT NOT NULL,
    "txId" TEXT NOT NULL,
    "signedConsent" TEXT NOT NULL,
    "signedConsentLen" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "userId" TEXT,
    "certificateId" TEXT,

    CONSTRAINT "SignedConsent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Revocation" (
    "id" TEXT NOT NULL,
    "certificateId" TEXT NOT NULL,
    "revokedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "reason" TEXT,

    CONSTRAINT "Revocation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CertificateAuthority" (
    "id" TEXT NOT NULL,
    "caCode" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "privateKey" TEXT NOT NULL,
    "publicKey" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CertificateAuthority_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OAuthClient" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecret" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "organizationId" TEXT NOT NULL,

    CONSTRAINT "OAuthClient_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Log" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "certificateId" TEXT,
    "actionType" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "details" TEXT,
    "orgCode" TEXT,

    CONSTRAINT "Log_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Account" (
    "seqno" SERIAL NOT NULL,
    "userId" TEXT,
    "accountNum" TEXT NOT NULL,
    "accountStatus" TEXT NOT NULL,
    "accountType" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "firstName" TEXT NOT NULL,
    "isConsent" BOOLEAN NOT NULL DEFAULT false,
    "isForeignDeposit" BOOLEAN NOT NULL DEFAULT false,
    "isMinus" BOOLEAN NOT NULL DEFAULT false,
    "lastName" TEXT NOT NULL,
    "orgCode" TEXT NOT NULL,
    "phoneNumber" TEXT NOT NULL,
    "pinCode" TEXT NOT NULL,
    "prodName" TEXT NOT NULL,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Account_pkey" PRIMARY KEY ("accountNum")
);

-- CreateTable
CREATE TABLE "DepositAccount" (
    "accountNum" TEXT NOT NULL,
    "balanceAmt" DECIMAL(65,30) NOT NULL,
    "commitAmt" DECIMAL(65,30) NOT NULL,
    "currencyCode" TEXT NOT NULL,
    "depositId" TEXT NOT NULL,
    "expDate" TIMESTAMP(3) NOT NULL,
    "issueDate" TIMESTAMP(3) NOT NULL,
    "lastPaidInCnt" INTEGER NOT NULL,
    "monthlyPaidInAmt" DECIMAL(65,30) NOT NULL,
    "offeredRate" DECIMAL(65,30) NOT NULL,
    "savingMethod" TEXT NOT NULL,
    "withdrawableAmt" DECIMAL(65,30) NOT NULL,

    CONSTRAINT "DepositAccount_pkey" PRIMARY KEY ("depositId")
);

-- CreateIndex
CREATE UNIQUE INDEX "Organization_orgCode_key" ON "Organization"("orgCode");

-- CreateIndex
CREATE UNIQUE INDEX "Organization_serialNum_key" ON "Organization"("serialNum");

-- CreateIndex
CREATE UNIQUE INDEX "CertificateAuthority_caCode_key" ON "CertificateAuthority"("caCode");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_clientId_key" ON "OAuthClient"("clientId");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_clientSecret_key" ON "OAuthClient"("clientSecret");

-- CreateIndex
CREATE UNIQUE INDEX "OAuthClient_organizationId_key" ON "OAuthClient"("organizationId");

-- CreateIndex
CREATE UNIQUE INDEX "Account_seqno_key" ON "Account"("seqno");

-- CreateIndex
CREATE UNIQUE INDEX "Account_accountNum_key" ON "Account"("accountNum");

-- CreateIndex
CREATE UNIQUE INDEX "DepositAccount_depositId_key" ON "DepositAccount"("depositId");

-- AddForeignKey
ALTER TABLE "User" ADD CONSTRAINT "User_orgCode_fkey" FOREIGN KEY ("orgCode") REFERENCES "Organization"("orgCode") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Certificate" ADD CONSTRAINT "Certificate_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Certificate" ADD CONSTRAINT "Certificate_certificateAuthorityId_fkey" FOREIGN KEY ("certificateAuthorityId") REFERENCES "CertificateAuthority"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Consent" ADD CONSTRAINT "Consent_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Consent" ADD CONSTRAINT "Consent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SignedConsent" ADD CONSTRAINT "SignedConsent_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SignedConsent" ADD CONSTRAINT "SignedConsent_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Revocation" ADD CONSTRAINT "Revocation_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OAuthClient" ADD CONSTRAINT "OAuthClient_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_certificateId_fkey" FOREIGN KEY ("certificateId") REFERENCES "Certificate"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_orgCode_fkey" FOREIGN KEY ("orgCode") REFERENCES "Organization"("orgCode") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Log" ADD CONSTRAINT "Log_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_orgCode_fkey" FOREIGN KEY ("orgCode") REFERENCES "Organization"("orgCode") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Account" ADD CONSTRAINT "Account_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DepositAccount" ADD CONSTRAINT "DepositAccount_accountNum_fkey" FOREIGN KEY ("accountNum") REFERENCES "Account"("accountNum") ON DELETE RESTRICT ON UPDATE CASCADE;
