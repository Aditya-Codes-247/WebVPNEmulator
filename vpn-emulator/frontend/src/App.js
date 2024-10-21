import React, { useState, useEffect } from 'react';
import ProtocolSelector from './components/ProtocolSelector';
import VPNAnimation from './components/VPNAnimation';

function App() {
  const [protocol, setProtocol] = useState('');
  const [dataFlow, setDataFlow] = useState([]);

  // Function to fetch data based on selected protocol
  const startVPN = async (protocol) => {
    try {
      const response = await fetch(`http://localhost:8000/start-vpn/${protocol}`);
      const data = await response.json();
      setDataFlow(data.dataFlow);
    } catch (error) {
      console.error('Error fetching VPN data:', error);
    }
  };

  // Handle protocol selection and fetching data
  const handleSelectProtocol = (protocol) => {
    setProtocol(protocol);
    startVPN(protocol);
  };

  return (
    <div className="App">
      <h1>VPN Protocol Emulator</h1>
      <ProtocolSelector onSelectProtocol={handleSelectProtocol} />
      
      {protocol && dataFlow.length > 0 && (
        <VPNAnimation protocol={protocol} dataFlow={dataFlow} />
      )}
    </div>
  );
}

export default App;
