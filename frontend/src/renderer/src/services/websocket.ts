/**
 * WebSocket client for real-time alerts, backed by socket.io-client.
 *
 * IMPORTANT (audit fix): the previous implementation used the browser's
 * native `WebSocket` class directly against the Flask-SocketIO backend.
 * Flask-SocketIO speaks the Engine.IO/Socket.IO protocol - a plain
 * WebSocket connection skips the required handshake
 * (`/socket.io/?EIO=4&transport=...`) and framing, so `new
 * WebSocket('ws://host:port')` could never actually exchange events with
 * `@socketio.on(...)` handlers on the server. This rewrite uses the
 * official socket.io-client, which is protocol-compatible.
 */

import { io, Socket } from 'socket.io-client';

export interface WebSocketEvent {
  type: string;
  data: any;
}

type AlertCallback = (alert: any) => void;
type StatusCallback = (status: any) => void;

// Configurable so the same bundle works against a local Electron-hosted
// backend and a deployed backend for the web build.
const SOCKET_URL = (import.meta as any).env?.VITE_WS_URL ||
  (import.meta as any).env?.VITE_API_BASE_URL?.replace(/\/api\/?$/, '') ||
  'http://localhost:5000';

class WebSocketClient {
  private socket: Socket | null = null;
  private alertCallbacks: AlertCallback[] = [];
  private statusCallbacks: StatusCallback[] = [];

  connect(url: string = SOCKET_URL): void {
    if (this.socket?.connected) return;

    this.socket = io(url, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 8000,
    });

    this.socket.on('connect', () => {
      console.log('Socket.IO connected');
    });

    this.socket.on('new_alert', (data) => {
      this.alertCallbacks.forEach((callback) => callback(data));
    });

    this.socket.on('system_status', (data) => {
      this.statusCallbacks.forEach((callback) => callback(data));
    });

    this.socket.on('connection_response', (data) => {
      console.log('Server handshake:', data);
    });

    this.socket.on('disconnect', (reason) => {
      console.log('Socket.IO disconnected:', reason);
    });

    this.socket.on('connect_error', (error) => {
      console.error('Socket.IO connection error:', error.message);
    });
  }

  subscribeAlerts(): void {
    this.socket?.emit('subscribe_alerts', {});
  }

  unsubscribeAlerts(): void {
    this.socket?.emit('unsubscribe_alerts', {});
  }

  getAlertHistory(limit: number = 100, offset: number = 0): void {
    this.socket?.emit('get_alert_history', { limit, offset });
  }

  onAlert(callback: AlertCallback): void {
    this.alertCallbacks.push(callback);
  }

  onStatus(callback: StatusCallback): void {
    this.statusCallbacks.push(callback);
  }

  disconnect(): void {
    this.socket?.disconnect();
    this.socket = null;
    this.alertCallbacks = [];
    this.statusCallbacks = [];
  }

  isConnected(): boolean {
    return !!this.socket?.connected;
  }
}

export const wsClient = new WebSocketClient();
export default wsClient;
