#!/usr/bin/env node
import 'source-map-support/register'
import * as cdk from 'aws-cdk-lib'
import { SignerEnclaveStack } from '../lib/signer-enclave-stack'

const app = new cdk.App()

new SignerEnclaveStack(app, 'SecureGitSigner', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
})
