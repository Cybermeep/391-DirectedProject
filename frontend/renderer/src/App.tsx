import React, { useEffect, useState } from 'react'

interface Alert {
  id: number
  alert_id: string
  timestamp: string
  attack_type: string
    severity: string
  source_ip: string
  dest_ip: string
  source_port: number
  dest_port: number
  protocol: string
  message: string
  ml_confidence: number
  status: string
}

// test_alert = {
//     'attack_type': 'PortScan',
//     'severity': 'medium',
//     'source_ip': '192.168.1.100',
//     'dest_ip': '10.0.0.1',
//     'protocol': 'TCP',
//     'message': 'Port scan detected',
//     'explanation': 'Multiple ports scanned from 192.168.1.100',
//     'ml_confidence': 0.82
// }

function App(): React.JSX.Element {
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [apiBase, setApiBase] = useState('http://localhost:5000')
  const [error, setError] = useState('')

  useEffect(() => {
    fetchAlerts()
  }, [])

  // Promise to fetch alerts from api
  // returns a promise and errors if nothing is found - bm
  async function fetchAlerts(): Promise<void> {
    setError('')
    try {
      const res = await fetch(`${apiBase}/api/alerts/`)
      if (res.ok) {
        const data = await res.json()
        setAlerts(data.alerts)
      } else {
        setError(`Server returned ${res.status}`)
      }
    } catch (e) {
      setError(`Could not reach API: ${apiBase}`)
    }
  }

  return (
    <div>
      <h1>NIDS ----</h1>

      <p>
        API URL:{' '}
        <input
          type="text"
          value={apiBase}
          onChange={(e) => setApiBase(e.target.value)}
        />{' '}
        <button onClick={fetchAlerts}>Fetch Alerts</button>
      </p>

      {error && <p>{error}</p>}

      <h2>Alerts: {alerts.length}</h2>

      {alerts.length === 0 ? (
        <p>No alerts.</p>
      ) : (
        <table border={1} cellPadding={4}>
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>Severity</th>
              <th>Attack Type</th>
              <th>Source IP</th>
              <th>Dest IP</th>
              <th>Protocol</th>
              <th>Confidence</th>
              <th>Message</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {/* I think this is all the fields for an alert? - bm */}
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>{alert.id}</td>
                <td>{alert.timestamp}</td>
                <td>{alert.severity}</td>
                <td>{alert.attack_type}</td>
                <td>{alert.source_ip}</td>
                <td>{alert.dest_ip}</td>
                <td>{alert.protocol}</td>
                <td>{alert.ml_confidence}</td>
                <td>{alert.message}</td>
                <td>{alert.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

export default App
