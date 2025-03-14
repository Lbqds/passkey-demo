import { sign as signRaw, binToHex, concatBytes, codec, bs58, NodeProvider, HexString, hexToBinUnsafe, web3, ONE_ALPH, publicKeyFromPrivateKey } from '@alephium/web3'
import { decode as cborDecode } from 'cbor2'
import * as elliptic from 'elliptic'
import { AsnParser } from '@peculiar/asn1-schema'
import { ECDSASigValue } from '@peculiar/asn1-ecc'
import * as BN from 'bn.js'

const nodeProvider = new NodeProvider('http://127.0.0.1:22973')
web3.setCurrentNodeProvider(nodeProvider)

export function isWalletExist(name: string): boolean {
  return localStorage.getItem(name) !== null
}

const curve = new elliptic.ec('p256')

function storeWallet(name: string, wallet: { publicKey: HexString, rawId: HexString }) {
  if (localStorage.getItem(name) !== null) throw new Error(`Wallet ${name} already exist`)
  const json = JSON.stringify(wallet)
  localStorage.setItem(name, json)
}

function getWallet(name: string): { publicKey: HexString, rawId: HexString } {
  const value = localStorage.getItem(name)
  if (value === null) throw new Error(`Wallet ${name} does not exist`)
  return JSON.parse(value)
}

function djb2(bytes: Uint8Array): number {
  let hash = 5381
  for (let i = 0; i < bytes.length; i++) {
    hash = (hash << 5) + hash + (bytes[`${i}`] & 0xff)
  }
  return hash
}

export function getWalletAddress(name: string): string {
  return encodePasskeyToBase58(hexToBinUnsafe(getWallet(name).publicKey))
}

function encodePasskeyToBase58(publicKey: Uint8Array): string {
  const encodedPublicKey = concatBytes([new Uint8Array([1]), publicKey])
  const checksum = djb2(encodedPublicKey)
  const bytes = concatBytes([
    new Uint8Array([4]),
    encodedPublicKey,
    codec.intAs4BytesCodec.encode(checksum),
  ])
  return bs58.encode(bytes)
}

export async function transfer(walletName: string, toAddress: string, amount: bigint) {
  const wallet = getWallet(walletName)
  const buildResult = await nodeProvider.transactions.postTransactionsBuild({
    fromPublicKey: wallet.publicKey,
    fromPublicKeyType: 'passkey',
    destinations: [{ address: toAddress, attoAlphAmount: amount.toString() }]
  })
  const signatures = await sign(buildResult.txId, wallet.rawId)
  const submitResult = await nodeProvider.multisig.postMultisigSubmit({
    unsignedTx: buildResult.unsignedTx,
    signatures: signatures.map((s) => binToHex(s)) }
  )
  return submitResult
}

async function sign(txId: HexString, walletId: HexString) {
  const bytes = hexToBinUnsafe(txId)
  const credential = await window.navigator.credentials.get({
    publicKey: {
      challenge: bytes,
      userVerification: "preferred",
      allowCredentials: [{ id: hexToBinUnsafe(walletId), type: "public-key" }]
    },
  }) as PublicKeyCredential
  const response = credential.response as AuthenticatorAssertionResponse
  const signature = parseSignature(new Uint8Array(response.signature))
  console.log(`tx id: ${txId}`)

  const authenticatorData = new Uint8Array(response.authenticatorData)
  const clientDataJSON = new Uint8Array(response.clientDataJSON)

  const array = encodeWebauthnPayload(authenticatorData, clientDataJSON)
  array.push(signature)
  return array
}

function encodeWebauthnPayload(authenticatorData: Uint8Array, clientDataJSON: Uint8Array) {
  const clientDataStr = new TextDecoder('utf-8').decode(clientDataJSON)
  console.log(`client data str: ${clientDataStr}`)
  const index0 = clientDataStr.indexOf("challenge") + 12
  const index1 = clientDataStr.indexOf('"', index0 + 1)
  const clientDataPrefixStr = clientDataStr.slice(0, index0)
  const clientDataSuffixStr = clientDataStr.slice(index1, clientDataStr.length)
  console.log(`${clientDataPrefixStr}`)
  console.log(`${clientDataSuffixStr}`)

  const encoder = new TextEncoder()
  const clientDataPrefix = encoder.encode(clientDataPrefixStr)
  const clientDataSuffix = encoder.encode(clientDataSuffixStr)

  const bytes1 = codec.byteStringCodec.encode(authenticatorData)
  const bytes2 = codec.byteStringCodec.encode(clientDataPrefix)
  const bytes3 = codec.byteStringCodec.encode(clientDataSuffix)
  const length = bytes1.length + bytes2.length + bytes3.length
  const totalLength = Math.ceil(length / 64) * 64
  const padding = new Uint8Array(totalLength - length).fill(0)
  const payload = concatBytes([bytes1, bytes2, bytes3, padding])
  console.log(`${binToHex(payload)}`)
  return Array.from({ length: payload.length / 64 }, (_, i) => payload.subarray(i * 64, (i + 1) * 64))
}

function parseSignature(signature: Uint8Array): Uint8Array {
  const parsedSignature = AsnParser.parse(signature, ECDSASigValue)
  let rBytes = new Uint8Array(parsedSignature.r)
  let sBytes = new Uint8Array(parsedSignature.s)

  if (shouldRemoveLeadingZero(rBytes)) {
    rBytes = rBytes.slice(1)
  }

  if (shouldRemoveLeadingZero(sBytes)) {
    sBytes = sBytes.slice(1)
  }

  const halfCurveOrder = curve.n!.shrn(1)
  const s = new BN.BN(sBytes)
  if (s > halfCurveOrder) {
    sBytes = new Uint8Array(curve.n!.sub(s).toArray('be', 32))
  }
  return new Uint8Array([...rBytes, ...sBytes])
}

// https://crypto.stackexchange.com/questions/57731/ecdsa-signature-rs-to-asn1-der-encoding-question
function shouldRemoveLeadingZero(bytes: Uint8Array): boolean {
  return bytes[0] === 0x0 && (bytes[1] & (1 << 7)) !== 0
}

export async function createPasskeyAccount(walletName: string) {
  if (isWalletExist(walletName)) throw new Error(`Wallet ${walletName} already exist`)
  const credential = await navigator.credentials.create({
    publicKey: {
      pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
      authenticatorSelection: {
        userVerification: 'preferred',
      },
      attestation: 'direct',
      challenge: window.crypto.getRandomValues(new Uint8Array(16)),
      rp: { name: 'alephium-passkey-wallet' },
      user: {
        name: walletName,
        displayName: walletName,
        id: window.crypto.getRandomValues(new Uint8Array(16))
      }
    }
  }) as PublicKeyCredential
  const response = credential.response as AuthenticatorAttestationResponse
  if (response.attestationObject === undefined) {
    throw new Error(`Expected an attestation response, but got ${credential.response}`)
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const attestationObject = cborDecode(new Uint8Array(response.attestationObject)) as any
  const authData = attestationObject.authData as Uint8Array

  const dataView = new DataView(new ArrayBuffer(2))
  const idLenBytes = authData.slice(53, 55)
  idLenBytes.forEach((value, index) => dataView.setUint8(index, value))
  const credentialIdLength = dataView.getUint16(0)
  const publicKeyBytes = authData.slice(55 + credentialIdLength)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const publicKeyObject = cborDecode(new Uint8Array(publicKeyBytes)) as any
  const publicKey = compressPublicKey(new Uint8Array(publicKeyObject.get(-2)), new Uint8Array(publicKeyObject.get(-3)))
  console.log(`public key: ${binToHex(publicKey)}`)
  console.log(`credential id: ${binToHex(new Uint8Array(credential.rawId))}`)
  console.log(`address: ${encodePasskeyToBase58(publicKey)}`)
  const address = encodePasskeyToBase58(publicKey)
  await transferFromDevGenesis(address)
  storeWallet(walletName, { publicKey: binToHex(publicKey), rawId: binToHex(new Uint8Array(credential.rawId)) })
}

function compressPublicKey(x: Uint8Array, y: Uint8Array): Uint8Array {
  const key = curve.keyFromPublic({ x: binToHex(x), y: binToHex(y) }, 'hex')
  return hexToBinUnsafe(key.getPublic(true, 'hex'))
}

async function transferFromDevGenesis(toAddress: string) {
  const privateKey = 'a642942e67258589cd2b1822c631506632db5a12aabcf413604e785300d762a5'
  const publicKey  = publicKeyFromPrivateKey(privateKey)
  const amount = 1000n * ONE_ALPH
  const buildResult = await nodeProvider.transactions.postTransactionsBuild({
    fromPublicKey: publicKey,
    destinations: [{ address: toAddress, attoAlphAmount: amount.toString() }]
  })
  const signature = signRaw(buildResult.txId, privateKey)
  await nodeProvider.transactions.postTransactionsSubmit({
    unsignedTx: buildResult.unsignedTx,
    signature
  })
}
