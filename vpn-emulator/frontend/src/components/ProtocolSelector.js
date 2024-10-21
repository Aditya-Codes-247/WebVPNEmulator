import React from 'react';

const ProtocolSelector = ({ onSelectProtocol }) => {
  const protocols = ['PPTP', 'L2TP', 'IPSec'];

  return (
    <div className="protocol-selector">
      <h2>Select VPN Protocol</h2>
      <div className="buttons">
        {protocols.map((protocol) => (
          <button key={protocol} onClick={() => onSelectProtocol(protocol)}>
            {protocol}
          </button>
        ))}
      </div>
    </div>
  );
};

export default ProtocolSelector;
