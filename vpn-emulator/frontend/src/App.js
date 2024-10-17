import React, { useState } from 'react';
import VPNConfig from './components/VPNConfig';
import VPNVisualization from './components/VPNVisualization';
import './App.css';

function App() {
  const [dataFlow, setDataFlow] = useState([]);

  const startVPN = async (protocol) => {
    const response = await fetch(`http://localhost:8000/start-vpn/${protocol}`);
    const result = await response.json();
    setDataFlow(result.dataFlow);
  };

  return (
    <div className="App">
      <h1>VPN Emulator</h1>
      <VPNConfig onStartVPN={startVPN} />
      <VPNVisualization dataFlow={dataFlow} />
    </div>
  );
}

export default App;
