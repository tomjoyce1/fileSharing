import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './styles/globals.css'
import { Buffer } from 'buffer/';
(window as any).Buffer = Buffer;

 ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
   </React.StrictMode>,
)
