import * as fs from 'fs'
import * as path from 'path'
import * as cdk from 'aws-cdk-lib'
import * as ec2 from 'aws-cdk-lib/aws-ec2'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as s3 from 'aws-cdk-lib/aws-s3'
import { Construct } from 'constructs'

/**
 * SignerEnclaveStack provisions a single Nitro-enabled EC2 host that runs the
 * secure-git-signer enclave. The flow after `cdk deploy`:
 *
 *   1. Build the EIF locally:  make eif
 *   2. Upload it to the bucket: aws s3 cp build/app.eif s3://<bucket>/app.eif
 *   3. The host's systemd service pulls the EIF and launches the enclave
 *      (it retries until the object exists, so order doesn't matter).
 */
export class SignerEnclaveStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props)

    // Bucket the host reads the EIF from. You upload build/app.eif here.
    const artifacts = new s3.Bucket(this, 'Artifacts', {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    })

    // One public subnet, no NAT gateway. The host needs outbound only for
    // package installs and pulling the EIF, which a public subnet provides.
    const vpc = new ec2.Vpc(this, 'Vpc', {
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [
        { name: 'public', subnetType: ec2.SubnetType.PUBLIC, cidrMask: 24 },
      ],
    })

    const sg = new ec2.SecurityGroup(this, 'EnclaveSg', {
      vpc,
      description: 'secure-git-signer enclave host',
      allowAllOutbound: true,
    })
    // Public HTTPS to nitriding. The client trusts the enclave via attestation,
    // not the source IP, so this is open to the internet.
    sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), 'HTTPS to the enclave')

    // SSM core lets you open a shell with `aws ssm start-session` — no SSH key
    // or port 22 required.
    const role = new iam.Role(this, 'EnclaveHostRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
      ],
    })
    artifacts.grantRead(role)

    // Embed build/run-enclave.sh at synth time so the host script can't drift
    // from the one in the repo.
    const runEnclave = fs.readFileSync(
      path.join(__dirname, '..', '..', 'build', 'run-enclave.sh'),
      'utf8',
    )
    const runEnclaveB64 = Buffer.from(runEnclave).toString('base64')

    const userData = ec2.UserData.forLinux()
    userData.addCommands(
      'set -eux',
      'dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel jq socat awscli',
      'usermod -aG ne ec2-user || true',
      'echo nitro_enclaves > /etc/modules-load.d/nitro_enclaves.conf',
      'modprobe nitro_enclaves || true',
      'mkdir -p /opt/secure-git-signer /etc/nitro_enclaves',

      // Reserve CPUs and memory for the enclave (must exceed the run-enclave.sh
      // request of cpu_count=2, memory=1024).
      "printf '---\\nmemory_mib: 2048\\ncpu_count: 2\\n' > /etc/nitro_enclaves/allocator.yaml",
      'systemctl enable --now nitro-enclaves-allocator.service',

      // gvproxy for nitriding's network bring-up.
      'curl -fsSL https://github.com/containers/gvisor-tap-vsock/releases/download/v0.8.8/gvproxy-linux-amd64 -o /opt/secure-git-signer/gvproxy',
      'chmod +x /opt/secure-git-signer/gvproxy',

      // run-enclave.sh, embedded above.
      `echo ${runEnclaveB64} | base64 -d > /opt/secure-git-signer/run-enclave.sh`,
      'chmod +x /opt/secure-git-signer/run-enclave.sh',

      // systemd unit: pull the EIF, then run the enclave; restart forever.
      `cat > /etc/systemd/system/secure-git-signer.service <<UNIT
[Unit]
Description=secure-git-signer Nitro Enclave
After=nitro-enclaves-allocator.service network-online.target
Wants=network-online.target

[Service]
Environment=ENCLAVE_CID=16
Environment=EIF_PATH=/opt/secure-git-signer/app.eif
Environment=GVPROXY_BIN=/opt/secure-git-signer/gvproxy
ExecStartPre=/usr/bin/aws s3 cp s3://${artifacts.bucketName}/app.eif /opt/secure-git-signer/app.eif
ExecStart=/usr/bin/env bash /opt/secure-git-signer/run-enclave.sh
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
UNIT`,
      'systemctl daemon-reload',
      'systemctl enable secure-git-signer.service',
      // Starts now and keeps retrying until app.eif lands in the bucket.
      'systemctl start secure-git-signer.service || true',
    )

    const host = new ec2.Instance(this, 'EnclaveHost', {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      // Nitro Enclaves need >= 4 vCPUs so 2 can be carved out for the enclave.
      instanceType: ec2.InstanceType.of(ec2.InstanceClass.C5, ec2.InstanceSize.XLARGE),
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.X86_64,
      }),
      securityGroup: sg,
      role,
      userData,
      enclaveEnabled: true,
      blockDevices: [
        { deviceName: '/dev/xvda', volume: ec2.BlockDeviceVolume.ebs(20, { encrypted: true }) },
      ],
    })

    new cdk.CfnOutput(this, 'ArtifactBucket', { value: artifacts.bucketName })
    new cdk.CfnOutput(this, 'UploadEifCommand', {
      value: `aws s3 cp build/app.eif s3://${artifacts.bucketName}/app.eif`,
    })
    new cdk.CfnOutput(this, 'InstanceId', { value: host.instanceId })
    new cdk.CfnOutput(this, 'EnclaveUrl', { value: `https://${host.instancePublicIp}` })
  }
}
