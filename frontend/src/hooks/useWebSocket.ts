import { useEffect, useRef, useState, useCallback } from "react";
import { WSMessage } from "../types";
import { auth } from "../api/client";

const POLICY_VIOLATION = 1008; // server rejected the token

function wsUrl(): string {
  const base =
    import.meta.env.VITE_WS_URL ||
    `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws/stream`;
  return `${base}?token=${encodeURIComponent(auth.getKey() ?? "")}`;
}

export function useWebSocket(onMessage: (msg: WSMessage) => void) {
  const ws = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState(false);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>();
  const heartbeat = useRef<ReturnType<typeof setInterval>>();
  const stopped = useRef(false);
  const attempts = useRef(0);

  const connect = useCallback(() => {
    if (stopped.current || ws.current?.readyState === WebSocket.OPEN) return;

    const socket = new WebSocket(wsUrl());

    socket.onopen = () => {
      attempts.current = 0;
      setConnected(true);
      heartbeat.current = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send("ping");
      }, 25000);
    };

    socket.onmessage = (event) => {
      if (event.data === "pong") return;
      try {
        onMessage(JSON.parse(event.data));
      } catch {
        /* ignore malformed frames */
      }
    };

    socket.onclose = (event) => {
      setConnected(false);
      clearInterval(heartbeat.current);
      if (stopped.current) return;
      if (event.code === POLICY_VIOLATION) {
        auth.clear();
        return;
      }
      // Exponential backoff, capped at 30s
      const delay = Math.min(30000, 1000 * 2 ** attempts.current++);
      reconnectTimer.current = setTimeout(connect, delay);
    };

    socket.onerror = () => socket.close();
    ws.current = socket;
  }, [onMessage]);

  useEffect(() => {
    stopped.current = false;
    connect();
    return () => {
      stopped.current = true;
      clearTimeout(reconnectTimer.current);
      clearInterval(heartbeat.current);
      ws.current?.close();
    };
  }, [connect]);

  return { connected };
}
