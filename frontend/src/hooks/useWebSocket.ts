import { useEffect, useRef, useState, useCallback } from "react";
import { WSMessage } from "../types";

const WS_URL = import.meta.env.VITE_WS_URL || "ws://localhost:8000/ws/stream";

export function useWebSocket(onMessage: (msg: WSMessage) => void) {
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();

  const connect = useCallback(() => {
    if (ws.current?.readyState === WebSocket.OPEN) return;

    const socket = new WebSocket(WS_URL);

    socket.onopen = () => {
      setConnected(true);
      // Heartbeat
      const hb = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send("ping");
      }, 25000);
      (socket as any)._hb = hb;
    };

    socket.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);
        onMessage(msg);
      } catch {}
    };

    socket.onclose = () => {
      setConnected(false);
      clearInterval((socket as any)._hb);
      reconnectTimer.current = setTimeout(connect, 3000);
    };

    socket.onerror = () => socket.close();

    ws.current = socket;
  }, [onMessage]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      ws.current?.close();
    };
  }, [connect]);

  return { connected };
}
