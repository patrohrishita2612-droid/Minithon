import { useEffect, useState } from 'react'

function App() {
  const [backendMessage, setBackendMessage] = useState('Loading from backend...')

  useEffect(() => {
    fetch('http://localhost:8000/api/hello')
      .then((res) => res.json())
      .then((data) => setBackendMessage(data.message))
      .catch((err) => setBackendMessage('Error connecting to backend: ' + err.message))
  }, [])

  return (
    <div style={{ padding: '40px', fontFamily: 'sans-serif', textAlign: 'center' }}>
      <h1>My Hackathon Project</h1>
      <p style={{ fontSize: '20px', color: 'green' }}>{backendMessage}</p>
    </div>
  )
}

export default App