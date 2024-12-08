import { useCallback, useState } from "react"
import { createPasskeyAccount, getWalletAddress, isWalletExist, transfer } from "./passkey"
import './index.css'
import { convertAlphAmountWithDecimals, NodeProvider, prettifyAttoAlphAmount } from "@alephium/web3"

const name = 'alephium-passkey-wallet'

function App() {
  const [isExist, setIsExist] = useState(isWalletExist(name))

  const [transferTo, setTransferTo] = useState<string>('')
  const [transferAmount, setTransferAmount] = useState<string>('')
  const [balance, setBalance] = useState<string | undefined>(undefined)

  const [txId, setTxId] = useState<string>('')

  const updateBalance = useCallback(async () => {
    const nodeProvider = new NodeProvider('http://127.0.0.1:22973')
    const address = getWalletAddress(name)
    const balances = await nodeProvider.addresses.getAddressesAddressBalance(address)
    setBalance(prettifyAttoAlphAmount(balances.balance))
  }, [setBalance])

  const onCreate = useCallback(async  () => {
    await createPasskeyAccount(name)
    setIsExist(true)
    await updateBalance()
  }, [updateBalance])

  const onTransfer = useCallback(async () => {
    const amount = convertAlphAmountWithDecimals(transferAmount)!
    const result = await transfer(name, transferTo, amount)
    setTxId(result.txId)
    await updateBalance()
  }, [transferTo, transferAmount, updateBalance])

  return (
    <div className="container">
      {!isExist ? (
        <button className="button" onClick={onCreate}>Register</button>
      ) : (
        <div className="form-container">
          <div className="form-group">
            <label htmlFor="transferTo">Transfer To:</label>
            <input
              id="transferTo"
              type="text"
              value={transferTo}
              onChange={(e) => setTransferTo(e.target.value)}
            />
          </div>
          <div style={{ marginTop: '20px' }}></div>
          <div style={{ marginTop: '20px' }}></div>
          <div className="form-group">
            <label htmlFor="transferAmount">Transfer Amount:</label>
            <input
              id="transferAmount"
              type="number"
              value={transferAmount}
              onChange={(e) => setTransferAmount(e.target.value)}
            />
          </div>
          <div style={{ marginTop: '20px' }}></div>
          <button className="button" onClick={onTransfer}>
            Transfer
          </button>
          <div style={{ marginTop: '20px' }}></div>
          <div className="text-info">
            <span style={{ fontSize: '20px' }}>Your address: {getWalletAddress(name)}</span>
          </div>
          {balance !== undefined ? (
            <>
              <div style={{ marginTop: '20px' }}></div>
                <div className="text-info">
                <span style={{ fontSize: '20px' }}>Balance: {balance} ALPH</span>
              </div>
            </>
          ) : (
            <></>
          )}
          {txId !== '' ? (
            <>
              <div style={{ marginTop: '20px' }}></div>
                <div className="text-info">
                <span style={{ fontSize: '20px' }}>Tx id: {txId}</span>
              </div>
            </>
          ) : (
            <></>
          )}
        </div>
      )}
    </div>
  );
}

export default App
